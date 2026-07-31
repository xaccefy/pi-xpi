---
name: cyberwf
description: Vulnerability discovery pipeline — the REQUIRED workflow whenever the task is to find vulnerabilities, hunt bugs, run a bug-bounty hunt, pentest, or security-audit a target. You are the coordinator — run the stage machine with subagent orchestration, state tracking, schema validation, reachability trace, gapfill loop, and structured reporting.
---

# Pipeline Orchestration Skill

## Your Role: Coordinator

**You are the pipeline coordinator.** You do NOT hunt, trace, or write PoCs yourself. You dispatch specialist subagents via the `subagent` tool and orchestrate their outputs.

- Every HUNT, TRACE, SKEPTIC, VALIDATE, CHAIN, and PATCH stage is executed by a `subagent({agent: "...", task: "..."})` call — not by you inline.
- You own: state tracking (casefile), scratchpad checkpoints, schema validation at stage boundaries, coverage aggregation, and the decision to advance/kill/retry each finding.
- If you find yourself reading source code or probing endpoints directly, **stop** — that is the subagent's job. Your job is to dispatch, validate the output against the schema, and record the result.
- The only stages you do yourself are RECON (see below) and REPORT (aggregate subagent outputs into the final report).

## Stage Machine

```
RECON(loop) → HUNT → GAPFIL(loop) → TRACE → SKEPTIC → VALIDATE → CHAIN → REPORT
  ↑_______________|__________________|            |
  └────────────── ROUNDS (re-hunt with new intel) ↓
         (traces into new hunts)             FIX (optional)
```

## ROUNDS: one pass is not enough

Real bug-bounty hunting is iterative: what you learn in one pass (tech hints, error messages, timing behavior, new parameters, new surface from traces) makes the next pass sharper. After the first REPORT, do NOT stop. Start a new ROUND: go back to HUNT with the accumulated intel and re-hunt every class that is not COVERED, plus re-probe previously dry endpoints with the new tricks you learned.

**Plateau stop condition** — stop when a full round produces ALL of:
- zero new findings (hypotheses),
- zero new reachable surface,
- zero new techniques from exploit_search that apply,
- and every class is COVERED, SKIPPED, or NOT_FOUND per the coverage rules.

There is no hard round cap; plateau detection is the cap. If a round yields anything new, keep looping. Budget-conscious? Note in the report that the run stopped at round N for budget, not for plateau.

SKEPTIC runs between TRACE and VALIDATE, but only for high-confidence findings (`confidence: high` — severity doesn't exist yet at this stage; the auditor sets confidence, the exploit agent sets severity after the PoC runs). The skeptic independently re-reads source to disprove the finding. If the skeptic says DISPROVEN, the finding is killed directly — no tie-breaker.

Finish coverage (hunt + gapfill) before spending trace budget. Trace only the hypotheses that survived a complete hunt, then validate the reachable ones.

Each stage produces a structured output. The next stage validates it before starting. If validation fails, the stage retries with repair guidance.

## Prerequisites — check before starting a run

The pipeline assumes the target is **in scope** and the agent has the tools to probe it. Before dispatching the first auditor, verify:

1. **Scope is defined AND matches the instruction.** Read the program's scope table (CSV/JSON from the bounty program). Do NOT match on the identifier alone — read the `instruction` column. Many assets are in scope only for a *restricted* subset (e.g. "limited to content and configuration issues", "API only", "excluding X"). Record the in-scope hosts/paths **and the scope instruction** in the pipeline-run case `target` + `assumptions`. Every probe must hit a host in scope AND the finding must fall within the instruction's allowed category. If scope is ambiguous, ask the user — do not guess.
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

**Directory layout** (created by `ScratchpadInit`):
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

**API (registered tools):** `ScratchpadInit`, `ScratchpadWrite`, `ScratchpadRead`, `ScratchpadCheckpoint`, `ScratchpadResume`, `ScratchpadPhaseDone`, `ScratchpadClear`. (The underlying module functions in `packages/pi-casefile/src/scratchpad.ts` are snake_case — always call the CamelCase tools.)

Stage names vs scratchpad phase names: the pipeline stage is spelled GAPFILL in prose, but the scratchpad phase key is `gapfil` — `ScratchpadCheckpoint(run_id, "gapfil", ...)` fails validation with "gapfill". Phase enum: recon, hunt, gapfil, trace, skeptic, validate, chain, patch, report.

**Rules:**
- Agents write artifacts to scratchpad, not to each other's output files (prevents echo chamber).
- Casefile still owns state transitions; scratchpad owns artifacts.
- Resume re-reads scratchpad artifacts, does not re-run completed phases (idempotent). A completed phase with a checkpoint artifact is a no-op on re-run.
- The `.scratchpad/` directory is preserved between runs; `--fresh` clears it.

## Resume + Checkpoints

After every phase: `ScratchpadCheckpoint(run_id, "<phase>", { ids: [<case-ids>], summary: "<one-line>" })`.

On pipeline start: `ScratchpadResume(run_id)` — if null, `ScratchpadInit(run_id)`. If resume returns a checkpoint, skip completed phases (check `ScratchpadPhaseDone` before each dispatch) and continue from the resumed next_phase. `--fresh` must call `ScratchpadClear(run_id)` FIRST and then `ScratchpadInit` — `ScratchpadInit` alone returns the old checkpoint untouched.

## Schema Validation at Stage Boundaries

Every stage output must pass the `PipelineSubmit` gate before the next stage begins. PipelineSubmit validates in code — required fields, enums, conditional requirements — and applies the deterministic pre-filter (test paths, hallucinated files, trivial dedup) on HUNT findings. Do NOT eyeball schemas yourself; the gate returns ACCEPTED, REPAIR (field-level errors, max 2 attempts per finding, then rejected), or REJECTED.

### Stage Schemas (in `schemas/` — enforced by PipelineSubmit):

| Stage | Schema | Required Fields |
|-------|--------|-----------------|
| **HUNT** | `schemas/stage-finding.json` | vuln_class, sink, entry_point, confidence, evidence; file+line for source targets, endpoint for live targets |
| **TRACE** | `schemas/stage-trace.json` | trace_result, entry_point, call_chain, defenses_checked, attacker_model |
| **SKEPTIC** | `schemas/stage-skeptic.json` | finding_id, verdict, reasoning, evidence_reviewed |
| **VALIDATE** | `schemas/stage-validation.json` | finding_id, status, technique_used, detection_method |
| **CHAIN** | `schemas/stage-chain.json` | chains[], summary |
| **REPORT** | `schemas/stage-report.json` | target, pipeline_status, findings, coverage, summary |

**Submission procedure:**
```
1. Subagent returns → PipelineSubmit(run_id, stage, output)
2. ACCEPTED  → advance, checkpoint, dispatch next stage
3. REPAIR    → return to the stage agent with the EXACT field errors the gate listed; re-submit
4. REJECTED  → repair budget exhausted or pre-filter hit (test path / hallucinated file / duplicate):
               record the stage state as failed (or the finding as noise) in the pipeline-run case,
               log the reason, decide: skip / different agent / abort
```

**Fail-closed rules (never bendy):**
- An unparseable or schema-invalid SKEPTIC output is **UNDETERMINED**, never DISPROVEN: repair it or re-dispatch; only a schema-valid `verdict: DISPROVEN` kills the finding.
- A TRACER that errors or fails validation counts as **UNREACHABLE** — the finding does not advance, it's not left indeterminate.
- Attach `outputSchema` (the schema's JSON from `schemas/`) to every subagent dispatch so the runtime validates structure before you ever see the output.

## Agent Dispatch Patterns

**These are commands to execute, not descriptions.** Each `subagent({...})` below is a real tool call you must make. Do not perform the stage's work yourself — dispatch the agent, then validate its output.

### RECON: Build the entry-point inventory (iterative)

RECON owns the run's coverage floor: hunts can only cover entry points recon found. Take it seriously — a shallow recon makes every later `NOT_FOUND` a lie.

For a code target this is lightweight (map routes, handlers, parsers, sinks with `grep`/`find` yourself). For a **live target**, run a recon loop:

1. Enumerate: subdomains (`subfinder`), live hosts (`httpx`), URLs (`katana`/`ffuf` crawling and fuzzing), JS files (mine them for routes and parameters).
2. Fingerprint: tech stack, frameworks, versions — then `exploit_search` for known CVEs and class-specific techniques for that stack.
3. Expand: every 4xx page, redirect, JS route, and API schema response is new surface — feed it back into enumeration. Repeat until expansion yields nothing new (recon plateau).
4. Record **every discovered entry point** (URL, method, parameters, auth state) plus tech notes into the scratchpad: `ScratchpadWrite(run_id, "recon", "entry-points.md", ...)`.

HUNT tasks must reference this inventory, and all coverage judgements are measured against it.

### HUNT: One agent per attack class

Dispatch auditor subagents concurrently (one per attack class) using the `subagent` tool's parallel mode:

```
subagent({ tasks: [
  { agent: "auditor", task: "Hunt for <class> vulnerabilities in <target/subsystem>. ...",
    outputSchema: <contents of schemas/stage-finding.json> },
  { agent: "auditor", task: "Hunt for <class2> vulnerabilities in <target/subsystem>. ...",
    outputSchema: <contents of schemas/stage-finding.json> },
]})
```

Coverage rule: the auditor must examine **every entry point in the recon inventory that can carry this class's input** — the recon inventory defines the floor, not a fixed number. After all auditors return, aggregate coverage. Coverage is per-entry-point, not a single tri-state — a class is only `NOT_FOUND` when every entry point identified in recon was actually examined:
```
COVERED:    class examined across all identified entry points (≥1 hypothesis OR each entry point ruled out with reason)
INCOMPLETE: class examined partially — some entry points never checked (stays in gapfill)
SKIPPED:    class not applicable (no surface, documented why)
NOT_FOUND:  class examined across ALL entry points and produced zero hypotheses (only when no entry point is unchecked)
```
A class with any unchecked entry point is `INCOMPLETE`, never `NOT_FOUND`. `INCOMPLETE` classes stay in the gapfill loop until every entry point is checked or explicitly ruled out.

### TRACE: One agent per finding

For each hypothesis that survived hunt + gapfill, dispatch a tracer subagent:

```
subagent({ agent: "tracer",
  task: "Trace whether attacker input reaches the sink at <file:line>. ...",
  outputSchema: <contents of schemas/stage-trace.json> })
```

Only findings with `TRACE RESULT: REACHABLE` advance to exploit.

**Live targets without source** — static reachability is impossible. The tracer's job becomes *dynamic reachability*: prove the endpoint exists, is reachable by an attacker at the claimed privilege level, and actually processes the input (reflected parameter, observable behavior change, error, timing delta). `TRACE RESULT: REACHABLE` then means "probed live and confirmed reachable", and `call_chain` holds the request/response evidence instead of a static chain. Findings for live targets use `endpoint` instead of `file`/`line` in the stage-finding schema — do not fail schema validation on missing file/line for live targets. The skeptic re-probes read-only to disprove instead of re-reading source.

### SKEPTIC: One agent per high-confidence traced finding (adversarial disconfirmation)

For every REACHABLE finding with `confidence: high` (severity is not assigned until VALIDATE), dispatch a skeptic subagent. The skeptic independently re-reads source to disprove the finding — it does not trust the auditor's or tracer's summary.

```
subagent({ agent: "skeptic",
  task: "Disprove finding <case-id>. vuln_class=<class>, sink=<file:line>, entry_point=<entry>.
         Trace result: REACHABLE via <call_chain>. Auditor evidence: <evidence>.
         Target: <target>. Scope instruction: <scope_instruction from program scope table — verbatim, or 'unrestricted'>.
         First verify the finding is in scope per the instruction. Then read the source yourself and try to disprove it.
         Output conforming to schemas/stage-skeptic.json.",
  turnBudget: { maxTurns: 12, graceTurns: 2 },
  outputSchema: <contents of schemas/stage-skeptic.json> })
```

Validate skeptic output against `schemas/stage-skeptic.json`:
- Must have finding_id, verdict (CONFIRMED|DISPROVEN), reasoning, evidence_reviewed
- If DISPROVEN: must have disproval_reason

**Skeptic verdict handling:**
- **CONFIRMED** — the skeptic agrees the finding is real. Write the skeptic's `disconfirmation_attempt` into the case's `disconfirmation` field via `CaseUpdate(id, { disconfirmation: <skeptic's attempt> })`. The finding advances to VALIDATE.
- **DISPROVEN** — the skeptic found a concrete reason the finding is false. Kill directly: `CaseUpdate(id, { status: "killed", nextStep: "killed: skeptic-disproven — <disproval_reason>" })`. No tie-breaker — a read-only re-read of source that found no path is the answer.

The skeptic's `disconfirmation_attempt` IS the case's disconfirmation record — it satisfies the disconfirmation gate before CONFIRMED. This is stronger than self-disconfirmation because a different agent produced it.

### VALIDATE: One agent per traced finding

For each reachable finding, dispatch an exploit subagent to write and run a PoC:

```
subagent({ agent: "exploit", task: "Phase 1: EXPLOIT. Finding <case-id>. ...",
  outputSchema: <contents of schemas/stage-validation.json> })
```

The exploit agent runs the PoC through `PromoteFinding` — you do not run it yourself. The case must be `investigating` with poc/evidence/impact/severity/target/disconfirmation on it before the gate accepts a run; the exploit agent is responsible for that CaseUpdate (keeping the skeptic's `disconfirmation` if present) before its first PromoteFinding call. Confirm the skeptic wrote the disconfirmation first; for non-skeptic findings the exploit agent writes its own.

### GAPFIL: Re-queue INCOMPLETE classes (targeted at the gap)

For each attack class with "INCOMPLETE" coverage, read the class's checked/unchecked entry-point list from the pipeline-run case, then dispatch an auditor subagent targeting the unchecked entries:

```
subagent({ agent: "auditor",
  task: "Hunt for <class> in <target>. Previous hunts found nothing.
           These entry points are ALREADY CHECKED — do not re-tread them: <checked list>.
           These entry points are UNCHECKED — examine each one: <unchecked list>.
           Use exploit_search for this specific class." })
```

The loop terminates when every class is COVERED, SKIPPED, or NOT_FOUND (i.e. zero `INCOMPLETE` remain), or after 3 iterations as a safety cap. Do NOT freeze a class as `NOT_FOUND` while unchecked entry points remain — if the cap hits with `INCOMPLETE` classes, report them as `INCOMPLETE` in coverage, not `NOT_FOUND`.

### FEEDBACK: Convert traces into new hunt tasks

For each TRACE that revealed a new attack surface (a subsystem touched by the call chain that wasn't previously audited), dispatch an auditor subagent:

```
subagent({ agent: "auditor", task: "Audit this subsystem: <subsystem>. The trace revealed it as untested attack surface." })
```

## Coverage Tracking

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

After all validations pass, dispatch the chain analyst subagent:

```
subagent({ agent: "chain",
  task: "Analyze confirmed findings for pipeline run <pipeline-case-id>.
           Tag: <pipeline-tag>. Target: <target>.
           Find exploit chains across ALL confirmed findings.",
  outputSchema: <contents of schemas/stage-chain.json> })
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
- SKEPTIC: ~15K per finding (only confidence == high)
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
- **No finding is confirmed until its target is verified in scope per the program's scope instruction** — not just the identifier. If the scope instruction restricts the asset to a subset (e.g. "CloudFront content/config only"), the finding must fall within that subset. Out-of-scope findings are killed, not confirmed.
- No finding advances without passing its stage schema. If the output is malformed, send it back.
- No finding is validated without a reachability trace showing REACHABLE.
- A high-confidence finding (`confidence: high`) is not validated until the skeptic stage runs — either the skeptic confirms it, or it's killed on DISPROVEN. **The skeptic must independently verify scope** — if the finding's target does not match the scope instruction, the skeptic outputs DISPROVEN with `disproval_reason: "out_of_scope"`, citing the scope instruction verbatim.
- A finding is only `confirmed` with evidence + poc + impact + severity and a PoC that exited 0 **with the verification_marker present in the output**. The PoC must hit the real target (or a faithful replica of the real vulnerable code) — no mocks for the exploitation step. **Severity is derived from what the PoC output actually demonstrates — not from theoretical/hypothetical impact.** The auditor does NOT set severity (use `confidence` instead). The exploit agent sets severity only after the PoC exits 0, mapping it to the proven impact. The skeptic checks for inflation.
- A patch isn't safe until a fresh tracer confirms the sink is no longer reachable.
- Coverage must be tracked per class with entry-point lists. Only `INCOMPLETE` classes re-queue in gapfill; `NOT_FOUND` requires an empty UNCHECKED list.
