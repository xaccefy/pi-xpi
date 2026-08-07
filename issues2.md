# XPI — Round 2: adversarial subagent review of the PoC gate and deliverables

Six specialist subagents (2× auditor, skeptic, tracer, chain, reporter-contract review)
independently attacked the "keep findings honest" machinery — the PoC verification gate
(`PromoteFinding` → `runPoc` → `promoteFindingResult`) and the deliverable tail
(`CaseContext` → reporter → `reported`). All six converged on the same core weakness set;
findings below are deduplicated. Statuses: **FIXED** (code change landed this round),
**DOCUMENTED** (limitation acknowledged, code cannot fully close), **DEFERRED** (fix
identified, not implemented).

The round-1 fixes (issues.md) are treated as fixed; every finding here is a residual of
those fixes or a new seam.

---

## The core weakness (all reviewers converged)

Every input to every deterministic gate — PoC script, control script, disconfirmation
script, both markers, severity, observation artifact, coverage notes, report file — is
authored by the same model the gates police. The machine verifies shapes, hashes, and
string presence/absence; it cannot verify what produced the bytes. The honest-PoC claim
is therefore bounded: gates raise the cost of cheating, they cannot make it impossible.

---

## FIXED this round (code)

### F1 — [P0→fixed] Two-file control cheat: the anti-cheat graded the agent's own second file
`index.ts` (PromoteFinding), `ledger.ts` (`promoteFindingResult`)
**Before:** `control_path` could be any file; a colluding model wrote `poc.py` printing the
marker unconditionally + `control.py` printing the liveness marker → every string check
passed. The "same script in control mode" contract was prompt text.
**Fix:** sha256(`control_path`) must equal sha256(`poc_path`), enforced at the tool BEFORE
any run and re-checked at the ledger (direct-caller bypass closed). A separately written
control file is rejected. The control run is now literally the same script, differing only
by the harness-set `PI_POC_MODE`.
**Residual (DOCUMENTED):** a colluding agent can still write a vacuous branch inside the
one shared script (control mode prints liveness without exercising anything). This is the
irreducible limit of any agent-written control; the docs now say so.

### F2 — [P1→fixed] 4000-char output slice hid the marker from the control check
`poc-runner.ts` (`sanitizeOutput` sliced to 4000), `index.ts`, `ledger.ts`
**Before:** marker-absence + liveness checks ran on the truncated display string. A script
printing liveness, then 4000+ chars of filler, then the vuln marker passed the control
gate — the marker was sliced off. The recorded evidence showed the same truncated window.
**Fix:** `PocRun.rawOutput` carries the full sanitized output (capped at 4 MiB, never
persisted — `stripRaw` drops it before the ledger write); all marker checks at tool and
ledger run on `rawOutput`. `truncated` flag surfaces when display was cut.

### F3 — [P1→fixed] Disconfirmation required only for high/critical → severity-downgrade ordering attack
`index.ts`, `ledger.ts`
**Before:** file the case as `medium`, promote (no disconfirmation script needed), then
`CaseUpdate(severity=critical)` → confirmed critical with zero executed disproof. Also,
the executed disconfirmation check verified only `completed && exit !== 0` — an `exit 1`
stub passed ("survived disproof" = agent-authored exit code).
**Fix:** `disconfirmation_path` is now REQUIRED for **every** promotion (tool + ledger),
killing the ordering attack entirely. The `exit 1` stub remains possible — DOCUMENTED as
the same irreducible agent-authored-script limit (the check now applies uniformly, and
workflow text tells the agent a stub means it doesn't understand the finding).

### F4 — [P1→fixed] Verification marker was tool-only; the ledger gate had a `!marker` escape
`ledger.ts` (`promoteFindingResult`)
**Before:** the ledger checked only `exitCode !== 0`; the marker check lived in the tool,
and `(!marker || !controlOutput.includes(marker))` weakened the control gate for any
direct caller omitting the marker.
**Fix:** `verificationMarker` is mandatory at the ledger (fails closed), the marker must be
present in the (untruncated) PoC output, and the control gate always enforces
marker-absence.

### F5 — [P1→fixed] Symlink dereference defeated PoC workspace containment
`poc-runner.ts` (`validatePocPath`)
**Before:** containment was checked on the lexical path only; `copyFileSync`/`readFileSync`
dereference symlinks. A workspace file symlinked to `$HOME/.env` passed validation, its
content was copied into the sandbox mount and could be echoed out as "command not found"
noise — full host-file disclosure into the PoC output.
**Fix:** `realpath` the resolved path and re-run containment; require a regular file
(`S_ISREG`) — FIFOs/devices/sockets rejected.

### F6 — [P1→fixed] PoC-controlled `[sandbox image error]` text prefix forced bare-host fallback
`poc-runner.ts` (`runPoc` local branch)
**Before:** infra-vs-PoC failure was distinguished by parsing output text the PoC fully
controls. With the operator's `PI_POC_ALLOW_LOCAL=1` set, a PoC printing that prefix as
its first line got re-run on the bare host (full env, operator privileges).
**Fix:** structured `infraError: boolean` set only by the runner's image-pull catch;
branch on the flag, never on output text.

### F7 — [P1→fixed] Report gate was existence-only: any file — even a directory — flipped the case to reported, permanently
`ledger.ts` (`validateCase`, `validateTransition`, new `validateReportFile`)
**Before:** `existsSync(reportPath)` was the entire machine check on the deliverable; a
1-line file passed and the case froze in `reported` forever. The six-point readiness
checklist was coordinator prompt text.
**Fix:** `validateReportFile` runs at every reported-state write and at the
`confirmed → reported` transition: regular file, size floor (200 B) and ceiling (2 MiB),
required section headings (Summary / Impact / Remediation per the reporter template), and
a forbidden-identifier scan (case id, report dir, `.scratchpad`, `casefile.db`,
PoC/control/disconfirmation basenames). A failing report keeps the case CONFIRMED; fix
the file, retry the transition.

### F8 — [P2→fixed] `reportedAt` stamped at CaseContext time, not when the report was written
`ledger.ts` (`writeCaseContext`, `updateCaseResult`)
**Before:** the disclosure timeline dated from bundle generation — potentially days before
the report existed (or never).
**Fix:** `reportedAt` is stamped when the `confirmed → reported` transition commits;
CaseContext no longer touches it.

### F9 — [P2→fixed] Observation provenance: same file as the PoC, or postdating the repro, passed
`ledger.ts` (`promoteFindingResult`)
**Before:** any file with a sha256 satisfied the artifact-backed-observation gate,
including the PoC file itself re-used as "the initial signal" or an item created after
the repro ran.
**Fix:** at promote time: observation sha256 ≠ poc sha256, basename ≠ poc basename,
`observation.createdAt ≤ verification.ranAt` (an observation recorded after the fact is
not the initial signal).
**Residual (DOCUMENTED):** a model writing a fake capture file seconds before `EvidenceAdd`
still passes — SHA-256 proves a file existed, not where it came from. This is the
irreducible provenance limit; the check now catches the lazy cheats.

### F10 — [P2→fixed] Kill-gate refutation items were prose-only
`ledger.ts` (`validateTransition`)
**Before:** killing an investigating/confirmed case needed a `refutation` item — with no
artifact requirement, a summary-only item was the same keyword-in-prose cheat wearing a
new hat.
**Fix:** refutation items used to kill advanced cases must be artifact-backed (sha256).

### F11 — [P2→fixed] Reporter contract: no untrusted-data rule; CVSS vector demanded but never stored
`agents/reporter.md`, `ledger.ts` (bundle header)
**Before:** every bundle field is model- or attacker-influenced (reflected response
bodies pasted into evidence), and the reporter had no untrusted-data framing — a hostile
target could steer the report via injected text. The fixed format demanded a CVSS 3.1
vector the pipeline never captures, forcing invention (the exact "never invent evidence"
violation).
**Fix:** reporter.md opens with an UNTRUSTED DATA warning (quote, never obey); the bundle
header carries the same banner (mirroring the case-list injection pattern). CVSS relaxed:
vector only when the case records one, else "not determined".

---

## DOCUMENTED residuals (code cannot fully close)

- **Agent-authored scripts (F1/F3):** same-file enforcement and uniform disconfirmation
  raise the bar; a colluding agent can still write a shared script whose control branch
  prints liveness without exercising anything. No string check can distinguish this from
  a genuine control.
- **Artifact provenance (F9):** any regular file the model writes is a valid artifact.
  The fix catches re-use and backdating; a freshly-written fake capture is
  indistinguishable from a real one by hash alone.
- **Host-network sandbox reaches operator localhost:** `local:true` shares the host
  network namespace — dev databases, admin UIs, and a localhost-bound MCP control plane
  are reachable from inside the sandbox. FS/caps/user isolation holds; the network
  identity is shared. Egress scoping (bridge + target allowlist) is a DEFERRED code fix;
  ops mitigation: don't bind control planes to loopback without auth.
- **Ledger DB is directly writable:** the agent has shell access to
  `.pi/casefile.db`; every tool gate is moot against direct DB edits. Documented posture
  (gates police tool-mediated writes).

## DEFERRED (identified, not implemented this round)

- **Scratchpad provenance:** `buildScratchpadSection` inlines agent-written scratchpad
  files into the CaseContext bundle as "pipeline artifacts" with no writer/timestamp
  attribution — a model can fabricate recon/trace/skeptic history that the reporter
  treats as audit trail. Fix: creator-stamp artifacts (harness-written via
  `pipeline_submit` vs agent-written) and tag them in the bundle. (Mitigation landed:
  the bundle now carries the untrusted-data banner.)
- **Coverage backing is self-satisfiable:** `recordCoverageResult` accepts any
  artifact-backed item on the case — which the model can create end-to-end (F9 residual).
  Fix: accept only harness-recorded `reproduction` items (or a harness `creator` stamp).
- **Dedup at promotion:** near-dup runs at add/update only; `assertPromotable` never
  re-checks, so finding-count inflation/suppression via title crafting survives. Fix: run
  `findDuplicateCaseInDb` inside `assertPromotable` (target is guaranteed there).
- **Pipeline report stage never cross-checks the ledger:** `stage-report` accepts any
  `findings`/`coverage` shapes; nothing verifies they correspond to confirmed cases with
  `pocVerified` or to `coverageSummary` cells. Fix: ledger cross-check in the report
  stage validator.
- **`PI_POC_TARGET` metacharacters:** the env contract passes the agent-controlled target
  string unvalidated; safe in the harness (argv `-e`), dangerous only if the agent's own
  script shells out to it. Fix: reject shell metacharacters in `sanitizePocEnv` values.
- **Disk-fill / container-leak:** `:rw` workspace mount uncapped; `docker rm -f` is
  best-effort. Fix: smaller tmpfs or `--ulimit`; ops: periodic `poc-runner-*` sweep.

## Clean verdicts (explicitly tested, no finding)

- Timeout/kill/ENOBUFS/spawn-error paths fail closed — no path yields exit 0 +
  `completed:true` without the container actually exiting 0; no verified-looking state
  persists after a failed run (single transaction in `promoteFindingResult`).
- No stale-output path: every run is a fresh spawn; the completion sentinel is unique
  per run.
- Filename shell injection: `shq` quoting + argv-only spawn verified inert (both sandbox
  and local); image selection bounded to 3 builtin images.
- ANSI/control-char stripping is fail-closed (cannot insert a marker).
- CaseContext cannot be skipped: `reportPath` has no other setter; invalid transitions
  to `reported` are blocked; the report file must pass the content gate (F7).

## Minimum dishonest path to REPORTED after this round

1. `CaseAdd` (disproveIf prose) → 2. `CaseUpdate` investigating (evidence/impact/severity
   prose) → 3. `EvidenceAdd` observation on a model-written file (F9 residual) →
   4. write ONE parameterized script (poc branch prints marker, control branch prints
   liveness, disconfirmation branch exits 1) → 5. `PromoteFinding` (all string checks
   pass; F1/F2/F3 raise the bar but the shared script is still agent-authored) →
   6. `CaseContext` → 7. reporter writes a report passing F7's content gate →
   8. `CaseUpdate(reported)`.
No step requires independent confirmation; every remaining cheat requires the model to
author a *coherent* fake (one script, one capture file, one report) rather than two
contradictory files. The machine floor is: two-file cheats, truncation cheats,
severity-ordering cheats, symlink escapes, and empty reports are now structurally
impossible; the coherent-single-actor fake is the documented boundary.
