# PoC Confirmation Trust Model

> Status: Tier 2 direct-response verification and reflection canaries are implemented. Source-separated OOB and general file/account/state oracles remain design work and fail closed.

## 1. TL;DR

Exit status, stdout, and `evidence.json` are inputs to confirmation, not proof. For a direct-response finding, XPI promotes only after the harness sends one immutable request template to both the case target and a distinct control origin, evaluates the same non-empty predicates against both responses, and observes `target_only`. For reflection-capable requests, the harness can additionally inject a fresh unpredictable token after the PoC exits and require target-only reflection. The response status, body hash, byte count, final URL, matcher result, and redacted canary result are recorded by the harness.

The governing rule is:

> **The judge must own (1) the evidence channel, (2) the secret, and (3) the execution of the predicate.**

The model still defines the request and success predicate, but it cannot author the observed response or weaken the control request. Blind/OOB classes are not confirmable through the built-in loopback listener because the PoC can reach it directly; those attempts remain investigating until source separation or an operator-owned external oracle exists.

## 2. What the gate actually verifies today

The current confirmation is the two-phase PromoteFinding → ConfirmFinding flow. A zero exit is required for run integrity, but it is never sufficient for promotion.

| Check | Evidence source | Predicate owner | Machine-judged? |
|---|---|---|---|
| Script exited zero, completed, and output capture completed | harness process result | harness | yes — necessary integrity only, never vulnerability proof |
| `evidence.json` exists, has a non-empty assertion, and its nonce matches | harness-owned dir + per-run random nonce | harness | yes — binds intent to the exact run |
| Two target runs deterministic (normalized evidence equal) | harness compares | harness | yes |
| Target `verify.url` belongs to the case target; control evidence belongs to the declared control | harness URL binding | harness | yes |
| Same request template executed against target and control | harness-owned HTTP client | harness | yes — only the origin changes; control-mode prose cannot weaken it |
| Target matches and control does not | harness-observed responses | harness | yes — required `target_only` predicate differential |
| Optional fresh canary appears on target but not control | harness-generated post-PoC token + harness responses | harness | yes — produces `canary_differential`; raw token is not persisted |
| Redirects remain network-safe | harness validates every hop, pins approved DNS answers at connect time, and strips credentials cross-origin | harness | yes |
| control == poc (sha256), PoC bytes unchanged at commit | harness | harness | yes — but only proves it is the *same* self-attesting script |
| Case target still equals the bundle's target, differs from control target | harness | harness | yes |
| Observation artifact is workspace-contained, non-symlink, durable, hashed, and predates repro | harness | harness | yes — existence/provenance, not semantic content |
| Main-agent verdict + fresh phase-2 replay: `re_execution_note`, `target_only`, `disconfirmation_attempt` | harness transcript + main agent's structured review | harness/main agent | yes for the replay; semantic review remains judgment |
| Private/internal replay | operator authorization + harness HTTP client | operator/harness | fail closed unless `PI_POC_ALLOW_PRIVATE_REPLAY=1` |
| Built-in loopback OOB callback | harness listener, but reachable by PoC | harness | diagnostic only; cannot promote without source separation |
| sandbox isolation, path containment, symlink rejection | harness | harness | yes |
| report file: size, required sections, forbidden identifiers | harness | harness | yes — but format, not truth |

What remains unverified: semantic impact, whether the selected predicate is strong enough for the claim, cryptographic main-agent identity provenance, blind interactions without source separation, and state-changing effects without a harness-owned account/state oracle. These are explicit limits, not paths that silently fall back to a worker verdict. A predicate-only differential is recorded as such; it is not relabeled as exploitation proof.

## 3. Cheats the current gate rejects

- `exit 0` with no evidence or an empty `expect` — rejected by the evidence contract.
- Mode-specific target/control JSON with no target effect — the harness ignores the control-mode request and derives an identical control request from the target template.
- A verify URL pointed at an unrelated known-good server — rejected by target binding.
- A public URL redirecting to loopback/private infrastructure — rejected at the redirect hop.
- Private-host replay without operator authorization — rejected; the main agent is not used as a fallback oracle.
- A PoC that curls its own loopback OOB token only in target mode — rejected because source separation is absent.

## 4. How real systems do machine verification

### 4.1 CGC / AIxCC — PoV as *data*, judge re-executes the target

In DARPA's Cyber Grand Challenge and its successor AIxCC, a Proof of Vulnerability is not a script that asserts success. It is an **input** (bytes, or an XML description of input). Verification is: the **judge** re-runs the *target binary* with that input and observes the abnormal execution itself — crash, sanitizer report, register/memory state. The CRS's claims are never trusted; the judge's own run is the verdict. AIxCC also penalized wrong submissions via an accuracy multiplier — noise was economically punished.

Transferable lesson: **separate PoV authorship from PoV execution, and make the judge's own observation of target state the verdict.** Where the target is a local replica (which XPI's sandbox already supports), the judge can absolutely re-run the target.

### 4.2 Interactsh / OAST — server-owned evidence channel

Interactsh (projectdiscovery) is the standard OAST (out-of-band) verifier: the client generates a unique interaction token (`*.oast.fun`), embeds it in the payload, and the **server's own logs** are the evidence — the scanner polls the server, it does not trust the scanner's stdout. The token's randomness makes pre-printing impossible; the server log lives outside the attacker's write path.

Transferable lesson: **the evidence channel must be outside the script's write path.** The harness runs its own listener; a per-run random token is injected via env; the verdict is "did MY listener log an interaction with THIS token" — read from the listener's own state, never from PoC stdout.

Interactsh's known limitation (relevant to us): it cannot by itself distinguish "the *target* made the interaction" from "the *attacker* made the interaction" when both share network egress. It mitigates with rich interaction metadata (source IP, User-Agent, DNS resolver, request shape). For XPI there is a hard fix available for sandboxed targets — the three-box model, §6.1.

### 4.3 Nuclei matchers — tool owns the fetch, author supplies only the predicate

Nuclei templates are the closest "code judging" model in daily use: the template author writes a *predicate* (status-code ranges, regex on body, DSL expressions like `contains`/`regex`), but the **tool performs the fetch itself** and applies the matcher to *its own* response. The author never gets to assert "it worked" — they only get to write the test, and the tool runs the test on evidence the tool itself acquired.

Transferable lesson: **split predicate definition from predicate execution + evidence acquisition.** The model may *define* what success looks like (that is inherently a judgment call), but the harness must *execute* the predicate against evidence the harness itself collected.

### 4.4 Canarytokens / known-answer testing

Canarytokens and similar systems plant a **secret the judge knows** (a unique token in a file, URL, or account) and score success by the secret appearing where it should not. The classic pentest version: the judge creates a canary file/account through a channel *it* controls, the exploit must exfiltrate it, and the judge compares the claimed exfiltration against its own copy of the secret. The attacker never gets to define what "the secret" is.

### 4.5 Empirical grounding: LLM pentest self-reporting is unreliable

The SoK "Hackers or Hallucinators? A Comprehensive Analysis of LLM-Based Automated Penetration Testing" (arXiv:2604.05719) reviewed 13 open-source AutoPT frameworks, ran 1,500+ execution logs under a unified benchmark, manually reviewed by 15+ researchers over four months. Its premise — and the literature it surveys — is that LLM frameworks routinely *report success without demonstrated impact*; distinguishing real findings from hallucinations is the central unsolved problem of the field. XPI's gate is one of the more honest attempts in this space, but its confirmation step inherits exactly this weakness: the verifier and the verified share one brain.

## 5. The design principle

A confirmation is machine-judged to the degree that the harness owns:

1. **The evidence channel** — where the evidence lives (harness listener logs, harness-side HTTP response, sandbox filesystem, target state). If the evidence is a string in the script's stdout, the channel is model-owned.
2. **The secret** — the thing whose appearance proves the effect (interaction token, canary value, planted file content). If the secret is chosen by the model, the model can print it unconditionally.
3. **Predicate execution** — the code that decides pass/fail (matcher on harness-fetched response, log query, file comparison). If the "predicate" is `output.includes(marker)` where the model chose the marker, the model chose the bar.

Current XPI direct-response tier: the harness owns evidence acquisition and predicate execution for both target and control, including connect-time DNS pinning. The worker-authored PoC owns predicate definition; the main agent reviews its semantic strength. For reflection, the harness also owns a post-PoC random secret and checks target-only appearance. XPI does not yet own a source-separated OOB channel or a general file/account/state oracle.

## 6. Remaining design — per bug class

Structured PoC output stays as the self-report and audit layer, but it cannot promote a case without a harness-owned oracle. Tier 2 is implemented; the remaining work is to extend equally strong oracles to blind and stateful classes.

### Tier 1 — Harness-owned callback (OOB classes: SSRF, blind RCE, open redirect, blind XSS, DNS exfil)

- Runner starts a small listener (HTTP + DNS) before the run; generates a per-run random token; exposes `PI_POC_CALLBACK_URL`/`PI_POC_CALLBACK_DOMAIN` to the sandbox.
- The PoC must cause the *target* to interact with the callback (SSRF payload → target fetches callback; blind RCE → `curl $CB`; etc.).
- Verdict: harness queries **its own listener log** for an interaction containing the token. PoC stdout is irrelevant to this check.
- The token is generated at run time and injected via env — the model cannot pre-print it because the value does not exist when the script is written.
- **Three-box model for sandboxed replicas (hard guarantee):** attacker box (the PoC sandbox, egress limited to the target box only) → target box (replica with real network) → callback box (harness-owned). A PoC cannot curl its own callback because its network namespace has no route to it; any interaction logged is target-originated by construction.
- **Live targets (best-effort):** interaction metadata (source IP/UA/request shape) is scored by simple harness heuristics — an interaction from the sandbox's own IP with the PoC's UA is rejected as self-interaction.

### Tier 2 — Request-spec + harness-side replay (direct-response classes: SQLi, reflected XSS, IDOR, traversal on live targets)

- The PoC writes a machine-readable evidence record to `PI_POC_EVIDENCE_DIR/evidence.json`: `{ verify: { method, url, headers, body, expect: { status, body_contains, body_regex } } }` — i.e., it supplies a bounded request and predicate, not the harness result.
- The harness sends that immutable request with its own HTTP client to both the case target and the operator-approved control, and applies the same expectation to each response.
- Only a conclusive target match and conclusive control non-match passes. A status-only expectation or a control transport failure is rejected.
- The PoC cannot author the harness's response observations or matcher result. This kills the "print success on any 200" class of cheat for response-visible findings.

### Tier 3 — General canary secrets + side-effect checks (sandbox-visible classes: local file read, file write, RCE on replica)

Reflection canaries are implemented for Tier 2 HTTP replay: declare one fixed `{{PI_POC_CANARY}}` placeholder, let the harness replace it after the PoC exits, and require the fresh value only in the target response. The remaining Tier 3 work is planting and observing secrets outside a response-reflection channel:

- The runner plants a canary file (random token) in a known path inside the sandbox before the run, and tells the PoC where via env.
- For "read arbitrary file" claims: the verdict is "the token appears in the harness-observed exfil channel" (Tier 1 callback for OOB, or Tier 2 capture for response-visible).
- For "write/execute" claims: a writable side-effect dir is mounted; the harness checks *itself* whether a file with the canary content appeared there.

### Tier 4 — Structured evidence record (all classes)

- Every PoC emits `evidence.json` (schema-validated): what it claims, what it observed, request/response pairs, timestamps.
- Even when the harness cannot independently verify (see §7), the structured record (a) makes the self-report auditable by the skeptic/reporter, (b) is the input carrier for Tiers 1–3, (c) is far harder to fake *consistently* across the control run than a one-line marker.
- Control-run consistency: the same record shape is required in control mode; a record that "succeeds" against a target it never reached is detectable by cross-checking fields (URL, status, body length) against harness-side observation where available.

### Tier 5 — Meta-level statistical trust

- **Accuracy ledger per agent/model:** track promote→later-kill rate and skeptic overrides. AIxCC's accuracy multiplier punished noise economically; a persistent reputation signal punishes it socially — findings from an agent with a high kill-rate get a mandatory skeptic pass and a harder gate. Cheap, code-only, no new sandbox machinery.
- **Multi-run determinism:** require the harness-side evidence to reproduce across 2 runs (catches flaky/one-shot cheating and flaky exploits alike). Costs one extra run.

## 7. What still cannot be machine-verified (honest limits)

- **State-changing bugs on live targets with no observable oracle.** If the exploit's only effect is "the victim's password changed" and the harness cannot observe the victim's account, no harness-owned channel exists. The case stays investigating. The fix is procedural: create a test account the harness controls, then verify the change against it.
- **A malicious model that performs the real attack and lies about it.** If the response never transits a harness-owned channel, the claim is unverifiable by construction. This is why Tier 2 (harness sends the request itself) matters: it removes the response from the model's write path for the most common classes.
- **Disconfirmation quality.** The main agent's disconfirmation remains a structured report. The phase-2 replay transcript is machine-bound to the verdict, but the orchestration identity and semantic quality of the disconfirmation are not.
- **Main-agent identity against a same-UID adversary.** The extension snapshots the worker role and treats it monotonically, so unsetting `PI_SUBAGENT_CHILD` cannot upgrade the running process. A shell-capable agent can still start a new process without the marker or mutate SQLite directly. Closing that boundary requires an orchestrator-issued capability or an OS-isolated ledger broker.
- **"Real impact" judgment** (is a leak actually sensitive, is RCE actually reachable from production). This is triage judgment; no harness channel exists. The report gate and human/vendor review remain the final arbiters.

## 8. Recommendation

Do these in order:

1. **Tier 1 source separation** — attacker box can reach only target; target can reach the operator-owned callback service.
2. **Tier 3 canaries/state oracles** for local replicas and test accounts.
3. **Bind main-agent provenance** to an orchestration-issued run identity instead of relying on the process-role boundary.
4. **Accuracy ledger** for agent/model promote-to-kill rates.

## 9. Sources

- SoK: DARPA's AI Cyber Challenge — competition design, PoV semantics (PoV = input; judge observes abnormal execution), accuracy multiplier. https://arxiv.org/html/2602.07666v5
- CGC Monitor: A Vetting System for the DARPA Cyber Grand Challenge (DFRWS). https://dfrws.org/presentation/cgc-monitor-a-vetting-system-for-the-darpa-cyber-grand-challenge/
- ProjectDiscovery Interactsh — server-side OOB interaction logs as evidence. https://github.com/projectdiscovery/interactsh
- Nuclei — tool-executed matchers on tool-fetched responses. https://docs.projectdiscovery.io/templates/protocols/http
- Hackers or Hallucinators? A Comprehensive Analysis of LLM-Based Automated Penetration Testing. https://arxiv.org/abs/2604.05719
- XPI internal: `.review-output/trustchain.md` (prior adversarial review, same conclusion), `packages/pi-casefile/src/index.ts` (PromoteFinding), `src/poc-runner.ts`, `src/ledger.ts` (promoteFindingResult).
