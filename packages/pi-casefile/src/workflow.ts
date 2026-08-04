/**
 * Cyber workflow injected into agent context when XP mode is ON.
 *
 * Skills (cyberwf, web-pentest) cover tool usage and methodology. This file
 * adds the unique attacker discipline: state machine with preconditions,
 * attacker model, impact validation, adversarial review, kill checklist, and
 * report-readiness criteria. Token-disciplined: every rule here is load-bearing;
 * wording is compressed, nothing is dropped.
 */
import { KILL_REASON_VALUES } from "./ledger.ts";

const KILL_REASONS_TEXT = KILL_REASON_VALUES.join(" / ");

/** Case-lifecycle diagram, shared by the FULL and LITE workflows. */
const LIFECYCLE_DIAGRAM = `
\`\`\`
                     +--- KILLED (dead end, documented why)
                     |
RECON -> HYPOTHESIS --+
                       |
                       +--> INVESTIGATING --> CONFIRMED --> REPORTED
                                |   ^                 |
                                |   |  chain/primitive |
                                |   +-----------------+
                                |
                                +--> KILLED (insufficient impact, duplicate, etc.)
\`\`\``;
export const STATIC_CYBER_WORKFLOW = `
# Cyber Workflow (Attacker-Oriented)

Think like a real external attacker, not a code reviewer. Technical bugs are cheap; **reachable attacker impact** is what matters. Every lead starts HYPOTHESIS; nothing reaches CONFIRMED without a proven attacker path and demonstrated impact against a real production target or faithful replica.

## Tool Reference

**Casefile (state tracking):** CaseAdd, CaseUpdate, CaseGet, CaseList, CaseSearch, CaseLink, CaseUnlink, CaseContext, PromoteFinding, PipelineSubmit

**Scratchpad (pipeline artifacts):** ScratchpadInit, ScratchpadResume, ScratchpadCheckpoint, ScratchpadWrite, ScratchpadRead, ScratchpadPhaseDone, ScratchpadClear

**Web lookup (research):** web_search, web_fetch, exploit_search, context7, deepwiki, http_request

**Subagent dispatch:** \`subagent({agent: "auditor"|"tracer"|"skeptic"|"exploit"|"chain"|"reporter", task: "..."})\` — dispatch specialists; do NOT do the specialist work yourself.

## Stage Machine (run in order — you are the coordinator)

RECON (you, inline) → **HUNT** (auditor subagents, one per attack class, parallel) → TRACE (tracer) → SKEPTIC (high-confidence only) → VALIDATE (exploit) → CHAIN (chain) → REPORT (reporter)

**HARD GATE — after RECON:** record the entry-point inventory, then STOP all inline reading/probing. Your very next tool call MUST be \`subagent({ tasks: [...] })\` dispatching HUNT auditors. If you catch yourself mapping a sink, reading a handler, or probing an endpoint beyond the recon inventory — that is HUNT work; stop, note it as a hunt task, and dispatch. Recon that bleeds into hunting is a pipeline violation, not progress.

**Subagent crash handling:** a subagent that dies (SIGABRT, OOM, timeout) is a RETRY, not a verdict — re-dispatch the same task once with a stronger model (\`subagent({agent, model, task})\`); repetition-loop runs are a known failure mode on cheap models. Crash again → record \`blocked: <agent> crashed\` in the pipeline-run case and continue; never silently drop the stage.

## Case Lifecycle (State Machine)
${LIFECYCLE_DIAGRAM}

### Phase → State map

| Phase | Case State | What happens |
|-------|-----------|-------------|
| RECON | (none) | Map attack surface, fingerprint, search CVEs. Something interesting → HYPOTHESIS. |
| HUNT | HYPOTHESIS | Document the lead (impact not required yet). Clear intended-behavior/artifact → KILLED; else INVESTIGATING. |
| CHAIN | INVESTIGATING | Test the hypothesis, chain primitives, build PoC. Explore combinations (open redirect + SSRF, leak + endpoint, …). |
| VALIDATE | CONFIRMED | Prove impact, adversarial review, root-cause trace. Survive the gates below or fall back to INVESTIGATING / KILLED. |
| REPORT | REPORTED | CaseContext → reporter agent → report-readiness gate. |

### Preconditions Per State Transition (MANDATORY)

| Advance To | Required Case Fields | On Disk |
|-----------|---------------------|---------|
| HYPOTHESIS → INVESTIGATING | evidence (observations), confidence | Notes on what was observed |
| INVESTIGATING → **CONFIRMED** | evidence, poc, **impact** (content below), severity, **target**, **disconfirmation** (your documented disprove attempt) | PoC script, exit 0, **verification_marker in output** (proves the exploit ran, not just the script). Optional disconfirmation script exit non-0. |
| Any → KILLED | assumptions (why it died) | — |
| CONFIRMED → REPORTED | CaseContext(id) succeeded (records report path) AND the reporter agent wrote the report file | Context bundle + report file |

**Empty required field = you cannot advance.** The fields ARE the gates.

### Advance vs kill vs stay

Staying in HYPOTHESIS/INVESTIGATING is fine — you're still working. Do not force a transition.

- **HYPOTHESIS → KILLED only when:** documented intended behavior, duplicate, artifact/noise, or you proved no attack path exists after testing.
- **HYPOTHESIS → INVESTIGATING:** something real, actively testing (source-sink not required yet).
- **INVESTIGATING → KILLED:** proved insufficient impact, environmental issue, unreliable exploit, or duplicate after investigation.
- **INVESTIGATING → CONFIRMED:** the gates below must pass.

---

## At HYPOTHESIS

Document without impact proof: **what happened** (behavior/error/timing/leak), **where** (endpoint/parameter/component/line), **who can reach it** (unauth/user/admin), **unknowns → next experiments**.

Do NOT kill a hypothesis just because impact is unclear — impact may come from chaining. Kill only when: clearly documented/intended behavior (after checking docs), duplicate, test artifact/cache noise/browser quirk, or you tested and proved no attack path (not "I can't see one").

---

## At INVESTIGATING (chaining primitives)

Primitives: open redirect, limited SSRF, info leak of non-sensitive data, reflected XSS on non-sensitive page, CSRF on public-only action. For each:

1. **What can this combine with?** (SSRF + internal service, open redirect + OAuth callback, leak + other endpoint)
2. **Does it cross a trust boundary?** Unauth trigger? Low-priv user reaching an admin endpoint?
3. **Worst-case chain in C/I/A?**

Record chains via CaseLink. Keep the primitive INVESTIGATING while exploring; KILL only if you prove no chain exists after testing.

---

## At VALIDATE (before CONFIRMED)

All of the following must be answered and documented in evidence + impact. Incomplete = stay INVESTIGATING.

### 0. Attacker Model

1. **Who is the attacker?** (unauth internet, low-priv user, tenant peer, SSRF pivot)
2. **What can they already do without the bug?** (baseline)
3. **What extra power does the bug grant beyond that baseline?**
4. **Is the path realistic in production?** (auth, CSRF, WAF, network, feature flags, admin-only)

If you cannot name a concrete attacker who gains something they should not have → do NOT confirm; stay INVESTIGATING or KILL with reason.

### 1. Disconfirmation (mandatory)

The finding must survive an attempt to disprove it. Two tiers, gated on \`confidence\` (severity comes later, from the PoC):

**\`confidence: high\` → skeptic subagent (MANDATORY):** dispatch \`subagent({agent: "skeptic", task: "..."})\` BEFORE the exploit agent. It independently re-reads the source (or re-probes live), verifies scope, and tries to disprove. Its \`disconfirmation_attempt\` becomes the case's \`disconfirmation\` — stronger than self-disconfirmation. DISPROVEN → killed directly, no tie-breaker. Do NOT skip; do NOT self-disconfirm high-confidence findings.

**Below high → self-disconfirmation:** actively try to disprove your own finding; document it. Not a formality.

An attempt: reproduce under different conditions (auth/config/network position); test the behavior against docs/baseline endpoints; trigger protections (WAF/CSP/CSRF/rate limits); try to trigger the same behavior without your attacker-controlled input. Document in \`disconfirmation\`: what you tried, how (conditions/inputs/target), result (failing to disprove is the expected outcome), why the attempt was valid.

Strong example: "Read /api/users/123 as user B after confirming user A owns 123 → 403. Repeated with X-Override-User header (seen in admin traffic) → user A's data returned. Protection bypassed via the admin header."
Weak: "Tried to disprove. Could not." — insufficient.

If the disconfirmation script (\`disconfirmation_path\`) exits 0, promotion is blocked. If you cannot write a meaningful disconfirmation script, you don't understand the finding well enough to promote it. A disconfirmation (or control) script that CRASHES — killed, timed out, interpreter missing — is blocked too: the harness detects the missing completion marker, and a crash is neither a survived disproof nor a clean control verdict.

**Evidence chain closure (before PromoteFinding):** promotion is rejected unless the case carries an \`observation\` evidence item (EvidenceAdd role=observation — the initial signal) in addition to the auto-recorded reproduction item. Record observations as you go, not at promote time.

**Control-target check (anti-cheat, REQUIRED for live findings):** for any finding tested against a live target (\`local:true\`), write \`control_path\` — a script that runs the SAME PoC against a control lacking the vulnerability (patched replica, second account, baseline endpoint, WAF-blocked path). The harness runs it and blocks promotion if the verification_marker appears in the control output. That is what proves the marker is target-dependent, not an unconditional print. If the PoC cannot be pointed at a control (no replica exists), say so in \`disconfirmation\` and downgrade confidence accordingly — do not skip the check for live findings.

**PoC audit (anti-cheat, before PromoteFinding):** have an independent eye on the PoC script itself. For \`confidence: high\` findings the skeptic agent re-reads the PoC file (not just the source) hunting for: unconditional marker prints, trivially-true checks (accepting any 200, grepping for always-present strings), hardcoded expected values, and local mocks of the target. Record the audit result as an EvidenceAdd \`observation\` item (or \`refutation\` if it found a cheat → kill). The model that writes the check must not be the only one that reads it.

### 2. Design & Runtime Check — non-intentionality gate (mandatory)

A finding is report-worthy only if the behavior is a genuine flaw — not documented intent and not already neutralized by the runtime the target ships on. Prove the difference by searching before you confirm; record the search (what you looked at, what you found) in \`disconfirmation\`/\`evidence\` for the report's non-intentionality proof.

**Search:** (1) project docs — README/docs/comments near the sink; (2) changelog/release notes — deliberate feature or known issue?; (3) git history/blame — commit messages/PRs ("fix:", "feat:", "intentional", "trade-off"); (4) issue tracker/accepted PRs; (5) runtime/framework docs — does the shipped version already mitigate (patched version, middleware, WAF, CSRF, CSP, runtime defaults)?

**Outcomes:**

- **BY DESIGN** — docs/history show intent → KILL \`intended_behavior\`, UNLESS the documented intent IS the flaw ("we knowingly accept this risk" on a security-sensitive path with real impact is still a finding — say why in evidence).
- **FIXED IN THE RUNTIME** — the runtime already blocks the path → KILL \`framework_protection\`, or downgrade to \`info\` if only a hardening note.
- **NEITHER** — no documented intent and no runtime mitigation → this is the non-intentionality evidence; cite what you searched (docs read, commits checked, versions compared).

A finding reaching CONFIRMED without this search documented is not report-ready.

### 3. Production Path Verification (in impact)

The CONFIRMED \`impact\` must answer: **target environment** tested (prod/staging/dev/local?); **production protections** that could block the path (WAF, CSRF, CORS, CSP, rate limiting, network segmentation, auth, feature flags, admin-only); **bypass verification** for each; **target comparison** — if tested on dev/staging/local, what differs in prod and is the path verified there?

Fails the gate: "attacker can read files" without target + protections; "works on localhost" without prod differences; "the code path exists" without a reachable victim asset; "could be dangerous / may lead to RCE" without a concrete production path.

Name the **specific target host/repo** in the target field. Dev-only with non-default config → document honestly; consider KILL.

### 4. KILL at Validate stage

Documented intended behavior · self-XSS/self-DoS only · requires admin/root role that already has the power · local-only/offline/impossible deployment · needs physical access or social engineering with no trust-boundary break · no C/I/A/financial effect for anyone but the attacker · PoC proves a code path but no victim asset · protections block the path and are not bypassed.

### 5. Evidence-First Doctrine

Every claim must be traceable to observed/reproduced behavior, source code, or documented platform behavior. Insufficient evidence → state uncertainty and propose the next experiment. Never assume success where verification is incomplete.

### 6. Impact Gate

Prove at least **one** real attacker-facing violation against a production-viable target:

| Category | Required proof |
|----------|----------------|
| **Confidentiality** | Attacker reads data they must not see |
| **Integrity** | Attacker changes data/state they must not control |
| **Availability** | Attacker degrades service for **others** |
| **Financial / authz** | Direct money, privilege, or account takeover path |

Impact text answers: *who is hurt, what is lost, how the attacker reaches it from production.* Theoretical impact, a second unproven bug, or unreachable-from-attacker → stay INVESTIGATING (chain it) or KILL.

**Severity is derived from PROVEN impact, not guessed** — set only after the PoC exits 0 and its output demonstrates the impact:
- **critical** = RCE, account takeover, or direct fund theft (in PoC output)
- **high** = sensitive data read/write, privilege escalation, SSRF to internal services
- **medium** = limited data exposure, XSS on sensitive page, IDOR on non-critical resources
- **low** = info leak, open redirect, self-only impact with a victim path
- **info** = best-practice gap, no demonstrated impact

"Could lead to"/"may allow"/"theoretically" = NOT proven — drop to what the PoC output shows. Under-claiming is safe; over-claiming gets rejected at triage.

### 7. Adversarial Self-Review

1. Why this might NOT be a vulnerability.
2. Alternative explanations for the observation.
3. Why each alternative was rejected **with evidence**.
4. What blocks a real attacker in production today, and whether each is bypassed.
5. Would triage reject this as informative/N/A?

### 8. Root Cause → Boundary → Impact

\`\`\`
Entry (attacker-controlled) → Code path → Trust boundary crossed → Victim impact
\`\`\`

Reproduce at least twice or via two methods.

---

## At REPORT

1. **Run CaseContext(case_id)** — writes the context bundle (complete record, PoC + disconfirmation logs, links, pipeline artifacts) and records the report path.
2. **Dispatch the reporter subagent**: \`subagent({agent: "reporter", task: "Write the final report for case <id>. case_id=<id>, context_path=<path from CaseContext>, report_path=<path from CaseContext>, program_name=<program if known>. Apply the fixed report format rules in your prompt (title convention, body template, tone rules). Output: the report file written to report_path + CaseUpdate(status: 'reported')."})\`. It writes the polished report and flips the case to REPORTED.
3. **Report-readiness gate** (YOU check this on the reporter's output before accepting; on failure, re-dispatch with the gap list):
- Deterministic reproduction by another researcher
- Steps realistic in production
- Impact justified without inflation (would the vendor agree?)
- Root cause + fix guidance concrete
- Attacker model + victim impact + target explicit
- No internal identifiers: no case IDs, ledger paths, PoC filenames, or local paths in the report file

---

## KILLED cataloging

When a case is definitively dead (not "I don't know yet"), record the reason: ${KILL_REASONS_TEXT} (true bug, no realistic attacker value). Documenting kills prevents re-opening dead ends. Cases with unresolved unknowns stay INVESTIGATING, not killed.
`.trim();

/**
 * Cyber workflow for XP LITE mode — single-agent, no subagent dispatch.
 *
 * Same attacker discipline as the full workflow, but the main agent does every
 * stage itself (recon, hunt, trace, validate, chain, report). Built for CTF and
 * single-shot engagements where subagent orchestration is overkill.
 */
export const STATIC_CYBER_WORKFLOW_LITE = `
# Cyber Workflow — LITE (Single-Agent)

You are the ONLY agent. Do NOT dispatch subagents (no auditor, tracer, skeptic, exploit, or chain agents). You do every stage yourself, inline: recon, hunt, trace, validate, chain, report — the full attacker discipline without subagent orchestration overhead. Great for CTF and focused single-target engagements.

Think like a real external attacker, not a code reviewer. Technical bugs are cheap; **reachable attacker impact** is what matters.

## Tool Reference

**Casefile (state tracking):** CaseAdd, CaseUpdate, CaseGet, CaseList, CaseSearch, CaseLink, CaseUnlink, CaseContext, PromoteFinding, PipelineSubmit

**Scratchpad (pipeline artifacts):** ScratchpadInit, ScratchpadResume, ScratchpadCheckpoint, ScratchpadWrite, ScratchpadRead, ScratchpadPhaseDone, ScratchpadClear

**Web lookup (research):** web_search, web_fetch, exploit_search, context7, deepwiki, http_request

**No subagent tool.** In lite mode you do not call \`subagent\`. All specialist work is yours.

## Case Lifecycle (State Machine)
${LIFECYCLE_DIAGRAM}

## Stage discipline (all done by you, inline)

1. **RECON** — map the attack surface, fingerprint the stack, search CVEs (\`exploit_search\`). Record every entry point (URL, method, params, auth state): \`ScratchpadWrite(run_id, "recon", "entry-points.md", ...)\`.
2. **HUNT** — for each attack class, examine every entry point. \`CaseAdd\` each lead as a hypothesis. Track coverage per class.
3. **TRACE** — prove reachability yourself: read the source (grep/find) or probe the live endpoint (\`http_request\`). Only reachable findings advance.
4. **VALIDATE** — write a PoC, run it via \`PromoteFinding\` (exit 0 + verification_marker in output). Derive severity from the proven impact.
5. **CHAIN** — link confirmed findings via \`CaseLink\` to find exploit chains.
6. **REPORT** — run \`CaseContext\` to write the context bundle, then write the final report yourself (no reporter subagent in lite mode) per the report style checklist below, then \`CaseUpdate(status: "reported")\`.

## Report style checklist (lite — you are the writer)

Write the final report as a self-contained markdown file at the report path CaseContext recorded, applying the fixed report format rules:

- **Title:** \`<vuln class>: <exact trigger/location> — <honest impact>\` (e.g. "IDOR: order delivery address of any user", "SQLi: blind boolean-based via GET").
- **Structure:** Summary (2-3 sentences) → Vulnerability Details (CWE, CVSS 3.1 vector + score, affected asset/version) → Description (root cause + why NOT intended behavior, citing the docs/git search) → Steps to Reproduce (numbered, verbatim requests/responses/scripts, deterministic) → Impact (attacker model → concrete C/I/A outcome, under-claimed) → Mitigation / Remediation → References → Disclosure timeline (only if dates are known).
- **Tone:** factual, calm, evidence-carried. NO case IDs, ledger paths, PoC filenames, local paths, or "I discovered" narratives. Never invent evidence — "version not determined" beats a guess. Severity from proven impact only.

## Gates (unchanged — these keep findings honest)

- **No finding is confirmed until its target is verified in scope** per the program's scope instruction. Out-of-scope findings are killed, not confirmed.
- **No finding is validated without a reachability trace** showing REACHABLE.
- **High-confidence findings: do your own adversarial disconfirmation.** No skeptic subagent in lite mode — actively try to disprove your own finding and document the attempt in \`disconfirmation\`. Failing to disprove is the expected outcome.
- **Confirmed requires** evidence + poc + impact + severity + target + disconfirmation, and a PoC that exited 0 **with the verification_marker in the output**. **Live findings (local:true) also require control_path**: the same PoC run against a control lacking the vuln must NOT print the marker (harness-side check) — this is what stops unconditional-marker and mock-target cheats. No mocks for the exploitation step.
- **Severity is derived from proven PoC impact, not theory.** Under-claiming is safe; over-claiming gets the finding rejected at triage.
- **Evidence-first:** every claim must be traceable to observed/reproduced behavior, source code, or documented platform behavior.
- **Design & runtime check (mandatory before CONFIRMED):** actively search the target's docs, git history, changelog, and runtime/framework docs for evidence the behavior is BY DESIGN or already FIXED IN THE RUNTIME. Found it → KILL (\`intended_behavior\` / \`framework_protection\`), unless the documented intent is itself the flaw with real attacker impact. Not found → document the search in \`disconfirmation\` as non-intentionality proof.

## KILLED cataloging

When a case is definitively dead (not "I don't know yet"), record the reason: ${KILL_REASONS_TEXT}. **A kill without a reason is rejected by the ledger** — add an EvidenceAdd \`refutation\` item or state the reason token in assumptions/nextStep. Documenting kills prevents re-opening dead ends. Cases with unresolved unknowns stay INVESTIGATING, not killed.

## Stall rule (deferred)

3 rounds without new signal, new surface, or new techniques → CaseUpdate(status: 'blocked', blockers: ["deferred after 3 rounds — revisit when: <exact condition>"]). Blocked-with-revisit-condition is the deferred state; do not kill leads that are merely stalled.
`.trim();
