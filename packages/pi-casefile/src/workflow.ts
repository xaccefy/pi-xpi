/**
 * Cyber workflow injected into agent context when XP mode is ON.
 *
 * Skills (pipeline, web-pentest) already cover tool usage and methodology.
 * This file adds the unique attacker discipline: state machine with
 * preconditions, attacker model, impact validation, adversarial review,
 * kill checklist, and report-readiness criteria.
 *
 * The case lifecycle (HYPOTHESIS -> INVESTIGATING -> CONFIRMED -> REPORTED)
 * maps to the pipeline's discovery stages. This file explains the gate
 * discipline applied at each transition.
 */
export const STATIC_CYBER_WORKFLOW = `
# Cyber Workflow (Attacker-Oriented)

Think like a real external attacker, not a code reviewer. Technical bugs are cheap; **reachable attacker impact** is what matters for bounty-valid findings.

Every lead starts HYPOTHESIS. Nothing reaches CONFIRMED without a proven attacker path and demonstrated impact against a real production target or faithful replica.

## Case Lifecycle (State Machine)

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
\`\`\`

### Phase -> State map

| Phase | Case State | What happens |
|-------|-----------|-------------|
| RECON | (none yet) | Map attack surface, fingerprint, search CVEs. When something interesting appears -> HYPOTHESIS. |
| HUNT | HYPOTHESIS | Document the lead. Impact not required yet. If it's a clear intended-behavior or artifact -> KILLED. Otherwise -> INVESTIGATING. |
| CHAIN | INVESTIGATING | Test the hypothesis, chain primitives, build PoC. Explore combinations (open redirect + SSRF, leak + other endpoint, etc.). |
| VALIDATE | CONFIRMED | Prove impact against production target, adversarial review, root-cause trace. Survive the gates below, or fall back to INVESTIGATING / KILLED. |
| REPORT | REPORTED | Write up, report-readiness gate, submit. |

### Preconditions Per State Transition (MANDATORY)

| Advance To | Required Case Fields | Must Exist on Disk |
|-----------|---------------------|--------------------|
| HYPOTHESIS -> INVESTIGATING | evidence (observations or initial findings), confidence | Notes on what was observed |
| INVESTIGATING -> **CONFIRMED** | evidence, poc (steps/script), **impact (see below for content requirements)**, severity, **target (host/repo/scope this affects)**, **disconfirmation (your documented attempt to disprove the finding)** | PoC script + run.log exit 0. Optionally, disconfirmation script run.log exit non-0 (finding survived the attempt to disprove). |
| Any -> KILLED | assumptions (why it died) | --- |
| CONFIRMED -> REPORTED | Only after CaseReport(id) succeeds | Report file |

**Rule: If a required field is empty, you cannot advance.** The fields are the gates.

### When to advance vs kill vs stay

Staying in HYPOTHESIS or INVESTIGATING is **fine** --- it means you're still working. Do not force a transition.

- **HYPOTHESIS -> KILLED only when**: it's documented intended behavior, duplicate, artifact/noise, or you proved no attack path exists after testing.
- **HYPOTHESIS -> INVESTIGATING**: you have something real and are actively testing. Source-sink not required yet.
- **INVESTIGATING -> KILLED**: you proved insufficient impact, environmental issue, unreliable exploit, or duplicate after investigation.
- **INVESTIGATING -> CONFIRMED**: strict gates below must pass.

---

## At HYPOTHESIS (just found something)

Document what you know without worrying about impact proof:

1. **What happened?** (behavior, error, timing, leak)
2. **Where?** (endpoint, parameter, component, line)
3. **Who can reach it?** (unauth, any user, admin only)
4. **What you don't know yet** -> next experiments

**Do not kill a hypothesis just because impact is unclear.** Impact may come from chaining.

**Kill a hypothesis only when:**
- It's clearly documented/intended behavior (after checking docs)
- It's a duplicate
- It's a test artifact, cache noise, browser quirk
- You tested and proved no attack path exists (not "I can't see one")

---

## At INVESTIGATING (chaining primitives)

Many findings start as primitives: open redirect, limited SSRF, info leak of non-sensitive data, reflected XSS on non-sensitive page, CSRF on public-only action.

For each primitive, ask:
1. **What can this combine with?** (SSRF + internal service, open redirect + OAuth callback, leak + other endpoint)
2. **Does the primitive cross a trust boundary?** Can an unauth user trigger it? Can a low-priv user reach an admin endpoint?
3. **What's the worst-case chain expressed in C/I/A?**

Record chains via CaseLink. Keep the primitive as INVESTIGATING while you explore. Only KILL if you prove no chain exists after testing.

---

## At VALIDATE (before advancing to CONFIRMED)

Before promoting to CONFIRMED, the following must be fully answered and documented in the case fields (evidence + impact). Incomplete answers = stay INVESTIGATING.

### 0. Attacker Model (must be in evidence or impact field)

1. **Who is the attacker?** (unauth internet, low-priv user, tenant peer, SSRF pivot, etc.)
2. **What can they already do without the bug?** (baseline privileges)
3. **What extra power does the bug grant beyond that baseline?**
4. **Is the path realistic in production?** (auth, CSRF, WAF, network, feature flags, admin-only required?)

If you cannot name a concrete attacker who gains something they should not have -> do **not** confirm. Stay INVESTIGATING or KILL with documented reason.

### 1. Disconfirmation Attempt (mandatory field before CONFIRMED)

Before promoting, you must actively attempt to disprove your own finding.
This is not a formality --- the attempt is documented in the \`disconfirmation\`
field and verified by the optional \`disconfirmation_path\` in PromoteFinding.

**What a disconfirmation attempt looks like:**

- Reproduce the finding under different conditions (different auth, different
  config, different network position). If it fails, you disproved the scope.
- Check if the behavior is intentional by testing against documentation or
  by trying to get the same result on a known-baseline endpoint.
- Attempt to trigger protections (WAF, CSP, CSRF, rate limits) that would
  block the path in production.
- Try to prove the root cause is wrong: can the same behavior be triggered
  without the attacker-controlled input you identified?

**Document the attempt in \`disconfirmation\` field.** Must include:
1. What you tried to do to disprove the finding
2. How you did it (conditions, inputs, target)
3. What result you got (if it failed to disprove, that's the expected outcome)
4. Why you believe the disconfirmation attempt was valid

**Strong disconfirmation that passes the gate:**
"Attempted to read /api/users/123 as user B after confirming user A owns
record 123. The endpoint returned 403 for user B, confirming the IDOR
protection works as expected. However, when we modified the request to
include the X-Override-User header seen in admin traffic, the endpoint
returned user A's data. The protection is bypassed via the admin header."

**Weak disconfirmation:**
"Tried to disprove. Could not."

If the disconfirmation script (disconfirmation_path) exits 0, the finding
is considered disproven and promotion is blocked. If you cannot write a
meaningful disconfirmation script, you may not understand the finding well
enough to promote it.

**Adversarial disconfirmation (skeptic subagent):** For findings at severity >= high, a dedicated skeptic subagent independently re-reads the source and tries to disprove the finding BEFORE the exploit agent runs. The skeptic's \`disconfirmation_attempt\` is written into this \`disconfirmation\` field by the harness — it satisfies this gate and is stronger than self-disconfirmation because a separate agent produced it. If the skeptic says DISPROVEN, the finding is killed directly. Self-disconfirmation still applies for findings below high severity.

### 2. Production Path Verification (must be in impact field)

The **impact** field for CONFIRMED must explicitly answer:

1. **Target environment:** Which host/repo/instance was this tested against? (prod, staging, dev, local?)
2. **Production protections:** What protections exist in production that could block this path? (WAF, CSRF tokens, CORS, CSP, rate limiting, network segmentation, auth, feature flags, admin-only access)
3. **Bypass verification:** For each protection, have you confirmed it is bypassed or absent?
4. **Target comparison:** If tested against dev/staging/local, what differs in production that could affect exploitability? Have you verified the path still works in the production configuration?

**Weak impact that fails this gate:**
- "Attacker can read files" without specifying which target and whether protections block it
- "This works on localhost" without verifying production differences
- "The code path exists" without proving a real victim asset is reachable
- "Could be dangerous" or "may lead to RCE" without a concrete production path

You must name the **specific target host/repo** in the target field. If the finding only works on a dev instance with non-default config, document that honestly and consider whether it's KILL-worthy.

### 2. KILL at Validate stage

Documented intended behavior
- Self-XSS / self-DoS only (attacker harms only their own session)
- Requires admin/root role that already has the same power
- Local-only, offline, or impossible deployment assumptions
- Needs physical access, social engineering with no trust-boundary break
- No C/I/A/financial effect for anyone but the attacker
- PoC proves a code path exists but not that any victim asset is affected
- Protections in production block the path and are not bypassed

### 3. Evidence-First Doctrine

Every claim must be traceable to observed/reproduced behavior, source code, or documented platform behavior. If evidence is insufficient: state uncertainty and propose the next experiment. Never assume success where verification is incomplete.

### 4. Impact Gate

Prove at least **one** real attacker-facing violation against a production-viable target:

| Category | Required proof |
|----------|----------------|
| **Confidentiality** | Attacker reads data they must not see |
| **Integrity** | Attacker changes data/state they must not control |
| **Availability** | Attacker degrades service for **others** |
| **Financial / authz** | Direct money, privilege, or account takeover path |

Impact text must answer: *who is hurt, what is lost, how the attacker reaches it from production.*

If impact is theoretical, needs a second unproven bug, or is not yet reachable from the attacker's position -> stay INVESTIGATING (chain it) or KILL.

### 5. Adversarial Self-Review

1. Why this might NOT be a vulnerability.
2. Alternative explanations for the observation.
3. Why each alternative was rejected **with evidence**.
4. What blocks a real attacker in production today and whether each is bypassed.
5. Would a program triage reject this as informative/N/A?

### 6. Root Cause -> Boundary -> Impact

\`\`\`
Entry (attacker-controlled) -> Code path -> Trust boundary crossed -> Victim impact
\`\`\`

Reproduce at least twice or via two methods.

---

## At REPORT (before advancing to REPORTED)

- Another researcher can reproduce deterministically
- Steps realistic in production
- Impact justified without inflation (would the vendor agree?)
- Root cause + fix guidance are concrete
- Attacker model + victim impact + target explicit

---

## KILLED cataloging

When a case is definitively dead (not "I don't know yet"), record the reason:
- intended_behavior / duplicate / framework_protection
- exploit_unreliable / insufficient_impact / environmental_issue
- not_applicable (true bug / interesting behavior, no realistic attacker value)

Documenting kills prevents re-opening dead ends. Cases with unresolved unknowns should stay INVESTIGATING, not killed.
`.trim();
