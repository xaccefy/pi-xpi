# PoC Confirmation — Implementation Spec

Supersedes the marker/exit-0 gate. Confirmation = harness-observed evidence + independent agent verdict. Exit code and markers are demoted to diagnostics.

## 1. Trust chain (what a promotion requires)

```
writer's claim
  → completed + outputComplete        (harness-measured: it ran, capture complete)
  → evidence.json (nonce-bound)       (writer's structured claim; schema-validated)
  → control-run evidence differential (code check: target ≈ control → not target-dependent)
  → confirmer verdict CONFIRMED       (independent agent, re-executes, adversarial)
  → ledger commit (re-checks all)     (defense-in-depth, same as today)
```

NOT_CONFIRMED is final for that attempt, no tie-breaker. Exit code recorded as diagnostic, never a gate.

## 2. Evidence contract

PoC gets two new env vars from the runner:

- `PI_POC_EVIDENCE_DIR` — writable dir in the sandbox; the PoC writes `evidence.json` there.
- `PI_POC_NONCE` — per-run random token; the PoC MUST echo it inside `evidence.json`. Binds the evidence to its run (kills copy-pasted evidence between runs).

`evidence.json` schema (validated by the harness before anything else):

```jsonc
{
  "nonce": "must match PI_POC_NONCE of this run",
  "claim": "what the exploit asserts (e.g. 'read /etc/passwd of target')",
  "verify": {                       // request spec the confirmer re-executes
    "method": "GET", "url": "...", "headers": {...}, "body": "...",
    "expect": { "status": [200], "body_contains": ["root:"], "body_regex": [] }
  },
  "observations": ["free-form what the script itself saw"],  // corroboration only
  "baseline": { "method": "GET", "url": "...", "body_contains": [] }  // optional differential
}
```

Control run produces its own `evidence.json` with its own nonce. The harness compares the two **structured evidence objects** (not strings): identical `claim`+`verify.expect` outcomes on target and control → blocked as not-target-dependent. This replaces marker-absence + liveness string checks.

## 3. Two-phase flow (tool layer cannot dispatch subagents)

Phase 1 — **PromoteFinding** (reworked, breaking):
1. `assertPromotable` (evidence chain, poc/impact/severity/target — observation artifact still required).
2. Run PoC against case target → evidence A.
3. Run same script against `control_target` → evidence B (same-script sha256 check stays).
4. Require on both: `completed`, `outputComplete`, valid nonce-bound evidence.json.
5. Cheap code differential: A and B both "succeed" → block.
6. Record `pending_confirmation` bundle on the case (paths, outputs, evidence, ranAt).
7. Return the bundle + the confirmer dispatch instruction (task text with case id + bundle path).

Coordinator dispatches the confirmer subagent (`agents/confirmer.md`, fresh context):
- Reads the PoC script, both evidence files, both raw outputs.
- Re-sends the `verify` request itself via `http_request`; compares its own response to `expect`.
- Compares target vs control evidence (behavior differential).
- Hunts cheats: unconditional success, trivially-true checks, hardcoded values, local mocks.
- Returns the structured verdict.

Phase 2 — **ConfirmFinding** (new tool):
1. Schema-validate the verdict.
2. Pending bundle exists and is not stale.
3. `NOT_CONFIRMED` → record reasoning on the case (assumptions), stays investigating. Retry allowed with a new confirmer dispatch; each attempt recorded.
4. `CONFIRMED` → `promoteFindingResult` commits: status confirmed, verdict + evidence hashes recorded, `disconfirmation` filled from the confirmer's own disproof attempt, reproduction evidence item created from `evidence.json` (hash), pending bundle cleared.

## 4. What the confirmer's disconfirmation replaces

The old `disconfirmation_path` script + non-zero-exit gate goes away. The confirmer's adversarial attempt ("assume fabricated, prove it real") is executed by an independent actor and becomes the case's `disconfirmation`. The `exit 1` cheat dies with the mechanism.

## 5. File-by-file update map

**New**
- `agents/confirmer.md` — agent definition: mandate, tool list (read, http_request, CaseGet, bash for re-run later), verdict contract, cheat-hunting checklist, severity sanity.
- `schemas/stage-confirm.json` — verdict schema (mirror pattern: doc) + parity test against the executable validator.
- `packages/pi-casefile/src/evidence.ts` — evidence schema + validator (TypeBox), nonce check, bundle builder (what the confirmer reviews), verdict validator.
- `docs/confirmation-design.md` — this spec.

**Modified**
- `packages/pi-casefile/src/poc-runner.ts` — create evidence dir in sandbox workspace, inject `PI_POC_EVIDENCE_DIR` + `PI_POC_NONCE`, parse/validate `evidence.json` into `PocRun.evidence`; exitCode re-documented as diagnostic.
- `packages/pi-casefile/src/index.ts` — PromoteFinding → phase 1 (drop marker/liveness/disconfirmation-param gates; add bundle + instruction); new ConfirmFinding tool; renderers + descriptions.
- `packages/pi-casefile/src/ledger.ts` — new columns (`pending_confirmation_json`, `confirmer_verdict_json`) via idempotent ALTER; `assertPromotable` drops the `disconfirmation` pre-requirement; `promoteFindingResult` rewritten: verdict-gated, nonce re-check, control differential, records verdict + evidence hashes, fills disconfirmation, clears pending.
- `packages/pi-casefile/src/workflow.ts` — "At VALIDATE" rewritten: two-phase flow, confirmer dispatch, evidence.json, demoted exit-0/marker language, disconfirmation-by-confirmer.
- `skills/cyberwf/SKILL.md`, `packages/pi-casefile/skills/casefile/SKILL.md`, `docs/guide.md`, `packages/pi-casefile/README.md` — tool reference + gate descriptions.
- Tests: `poc-runner.test.ts` (evidence collection, nonce), `ledger.test.ts` (verdict-gated promotion, differential block), `index.test.ts` (two-phase, stale bundle), new parity test for stage-confirm.

**Removed**
- PromoteFinding params: `verification_marker`, `control_liveness_marker`, `disconfirmation_path` (breaking change).
- Marker presence/absence checks, liveness check, disconfirmation-script gate in index.ts + ledger.ts.

## 6. Unchanged (keep-list)

Sandbox + sentinel + containment, `completed`/`outputComplete`, same-script control sha256, observation artifact requirement, state machine + proof-bound field locks, report content gate, scratchpad + PipelineSubmit, evidence-chain closure at report time.

## 7. Open decisions (block on these before coding)

1. **Double target run for determinism** — run the PoC twice and require both evidence files consistent, or once? (Cost: +1 sandbox run per promotion. Lean: yes — it also gives the confirmer two transcripts to compare.)
2. **Confirmer model** — must differ from the writer. Enforce via operator env (`PI_CONFIRMER_MODEL`) with a hard fail when unset, or soft (workflow text only)?
3. **Confirmer re-running the PoC** — v1: replay-only (http_request). Sandboxed re-run via a harness tool is v2. Confirm.
4. **Pending-bundle staleness** — TTL between phase 1 and ConfirmFinding (e.g. 1h) or unlimited?
5. **Cheap code differential** — in v1 (step 2.5) or deferred to the confirmer only?

## 8. Migration

Existing confirmed cases keep their marker-based verification records (read-only, backward compatible). Only new promotions use the new path. No data rewrite needed; new columns are additive.
