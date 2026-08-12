# PoC Confirmation Trust Model — Research

> Status: research / design. Not implemented.
> Question: the PoC confirmation gate is not really *code judging* the exploit — it is the model judging itself. What would machine verification actually look like, and what can be done cheaply?

## 1. TL;DR

Every gate that looks like machine verification (exit 0, verification marker, same-script control, liveness marker, executed disconfirmation, hashed observation artifact) runs on **files and strings the model itself wrote**. The harness checks *presence/absence of strings the model chose*, printed by *a script the model wrote*, describing *a claim the model made*. Nothing the harness independently observes — no network traffic, no target state, no planted secret — is used in the verdict.

The fix is a trust-model shift, not more string checks:

> **The judge must own (1) the evidence channel, (2) the secret, and (3) the execution of the predicate.**

Today the model owns all three. Industry systems that do real machine verification (CGC/AIxCC PoVs, interactsh/OAST, Nuclei matchers, canarytokens) each own at least one, usually two.

## 2. What the gate actually verifies today

The marker/exit-0 gates described in earlier drafts are gone: exit codes and output markers are **diagnostics**, and the current confirmation is the two-phase PromoteFinding → ConfirmFinding flow with a nonce-bound `evidence.json` contract and an independent confirmer re-execution.

| Check | Evidence source | Predicate owner | Machine-judged? |
|---|---|---|---|
| Script ran to completion + output capture complete | harness (sentinel / spawn result) | harness | yes |
| `evidence.json` exists, schema-valid, nonce matches the run | harness-owned dir + per-run random nonce | harness | yes — binds the file to the exact run (kills copy-pasted evidence) |
| Two target runs deterministic (normalized evidence equal) | harness compares | harness | yes |
| Control evidence differs from target's (target-dependent claim) | harness compares | harness | yes — but the evidence objects are **authored by the script** |
| control == poc (sha256), PoC bytes unchanged at commit | harness | harness | yes — but only proves it is the *same* self-attesting script |
| Case target still equals the bundle's target, differs from control target | harness | harness | yes |
| Observation artifact exists + hashes, predates the repro | harness | harness | yes — existence/hash; **content never judged** |
| Confirmer verdict: `re_executed: true`, `target_only`, `disconfirmation_attempt` | **confirmer agent's self-report** | **confirmer** | shape-checked only; the re-execution itself is not observed |
| sandbox isolation, path containment, symlink rejection | harness | harness | yes |
| report file: size, required sections, forbidden identifiers | harness | harness | yes — but format, not truth |

What is *not* verified anywhere: that the target was contacted, that a request caused the claimed effect, that data was actually exfiltrated, that the response contained what the script says it contained — and, in the current design, that the confirmer actually re-sent the verify request (its `re_executed` is a self-reported boolean). The PoC script still branches on `PI_POC_MODE`/`PI_POC_TARGET`, so the evidence differential can be script-authored; the confirmer's independent re-execution is the counter-check, and it is trusted on its word.

## 3. Concrete cheat scripts that pass every gate today

A malicious model (or a prompt-injected PoC from a cloned repo — the workflow itself clones untrusted code) can pass the full gate with zero exploitation:

```sh
#!/bin/sh
# poc.sh — passes all current checks, exploits nothing
if [ "$PI_POC_MODE" = "control" ]; then
  echo "CONTROL_REACHED_c1"        # liveness marker
  exit 0                            # no vuln marker → control "clean"
fi
echo "VULN_CONFIRMED_c1"           # verification marker, unconditional
exit 0
```

- sha256(control)==sha256(poc): same file. ✓
- control prints liveness, no marker: ✓
- disconfirmation script: `#!/bin/sh\nexit 1` — "finding survived disproof". ✓
- observation artifact: any existing file, EvidenceAdd'd. ✓
- PoC exit 0, marker present, output complete. ✓

**The same-file control gate is circumventable by branching on `PI_POC_MODE`/`PI_POC_TARGET`** — the model knows both values. The gates are honestly calibrated against an *honest-but-sloppy* model (they reliably catch an honest PoC accidentally printing its marker unconditionally, and they make sloppiness costly), but they are *theater* against a model that chooses to cheat. The trust-chain review in `.review-output/trustchain.md` reached the same conclusion: "The ledger checks shapes, transitions, and string presence/absence — never provenance, never semantics."

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

Current XPI: owns none of the three at the confirmation step. Marker, liveness string, and control behavior are all model-authored; the only harness-owned checks are process-level (ran, completed, captured) and file-level (exists, hashes, same-file).

## 6. Proposal — per bug class

The marker system stays as the *self-report* layer (it documents intent and catches honest sloppiness), but confirmation becomes a **harness-observed evidence check**. PoC scripts gain an optional `PI_POC_EVIDENCE_DIR` / `PI_POC_CALLBACK_URL` contract; promotion requires the harness-side check to pass *in addition to* the self-report.

### Tier 1 — Harness-owned callback (OOB classes: SSRF, blind RCE, open redirect, blind XSS, DNS exfil)

- Runner starts a small listener (HTTP + DNS) before the run; generates a per-run random token; exposes `PI_POC_CALLBACK_URL`/`PI_POC_CALLBACK_DOMAIN` to the sandbox.
- The PoC must cause the *target* to interact with the callback (SSRF payload → target fetches callback; blind RCE → `curl $CB`; etc.).
- Verdict: harness queries **its own listener log** for an interaction containing the token. PoC stdout is irrelevant to this check.
- The token is generated at run time and injected via env — the model cannot pre-print it because the value does not exist when the script is written.
- **Three-box model for sandboxed replicas (hard guarantee):** attacker box (the PoC sandbox, egress limited to the target box only) → target box (replica with real network) → callback box (harness-owned). A PoC cannot curl its own callback because its network namespace has no route to it; any interaction logged is target-originated by construction.
- **Live targets (best-effort):** interaction metadata (source IP/UA/request shape) is scored by simple harness heuristics — an interaction from the sandbox's own IP with the PoC's UA is rejected as self-interaction.

### Tier 2 — Request-spec + harness-side replay (direct-response classes: SQLi, reflected XSS, IDOR, traversal on live targets)

- The PoC writes a machine-readable evidence record to `PI_POC_EVIDENCE_DIR/evidence.json`: `{ request: { method, url, headers, body }, expectation: { status: [..], body_contains: [...], body_regex: [...] } }` — i.e., the model supplies the *predicate*, not the result.
- The harness **sends the request itself** with its own HTTP client and applies the expectation to the response *it* received.
- Differential mode: the harness sends the baseline request and the attack request and applies a comparison predicate (e.g., "attack response contains a value the baseline response does not").
- The model never gets to see the final response and assert on it — the harness's client and matcher code do. This kills the "print marker on any 200" cheat for response-visible classes.

### Tier 3 — Canary secrets + side-effect checks (sandbox-visible classes: local file read, file write, RCE on replica)

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

- **State-changing bugs on live targets with no observable oracle.** If the exploit's only effect is "the victim's password changed" and the harness cannot observe the victim's account, no harness-owned channel exists. The marker stays the only signal. The fix is procedural, not mechanical: the workflow should demand an *oracle* (create a test account the harness controls, then verify the change against it — known-answer testing).
- **A malicious model that performs the real attack and lies about it.** If the response never transits a harness-owned channel, the claim is unverifiable by construction. This is why Tier 2 (harness sends the request itself) matters: it removes the response from the model's write path for the most common classes.
- **Disconfirmation quality.** `exit 1` on an empty script will always pass the *executed* disconfirmation gate. The content of the disproof remains a judgment call — the skeptic agent (a different model, fresh context) is the right tool, but that stays prompt-level. Making the disconfirmation emit a structured record (what was tried, what was observed) at least makes it reviewable.
- **"Real impact" judgment** (is a leak actually sensitive, is RCE actually reachable from production). This is triage judgment; no harness channel exists. The report gate and human/vendor review remain the final arbiters.

## 8. Recommendation

Do these in order:

1. **Tier 2 (request-spec + harness-side replay)** — covers the largest share of real findings (direct-response web bugs), pure code, no new infra. Reuses the existing sandbox: the harness's own fetch to the live target or replica.
2. **Tier 1 (harness-owned callback, three-box for replicas)** — covers the OOB classes where no other verification exists; the DNS/HTTP listener is ~200 lines; the three-box model makes it a hard guarantee for sandboxed targets.
3. **Tier 4 (evidence.json schema)** — prerequisite discipline for both; also feeds the reporter.
4. **Tier 5 (accuracy ledger + determinism)** — cheap, code-only, increases cost of cheating over time.
5. **Tier 3 (canaries)** — where sandbox-visible classes matter; easy once the evidence contract exists.

Keep the marker + same-file control + liveness checks: they remain the correct defense against honest sloppiness and they make the *self-report* explicit. But relabel them in docs as **self-report**, and make the harness-observed check the confirmation.

## 9. Sources

- SoK: DARPA's AI Cyber Challenge — competition design, PoV semantics (PoV = input; judge observes abnormal execution), accuracy multiplier. https://arxiv.org/html/2602.07666v5
- CGC Monitor: A Vetting System for the DARPA Cyber Grand Challenge (DFRWS). https://dfrws.org/presentation/cgc-monitor-a-vetting-system-for-the-darpa-cyber-grand-challenge/
- ProjectDiscovery Interactsh — server-side OOB interaction logs as evidence. https://github.com/projectdiscovery/interactsh
- Nuclei — tool-executed matchers on tool-fetched responses. https://docs.projectdiscovery.io/templates/protocols/http
- Hackers or Hallucinators? A Comprehensive Analysis of LLM-Based Automated Penetration Testing. https://arxiv.org/abs/2604.05719
- XPI internal: `.review-output/trustchain.md` (prior adversarial review, same conclusion), `packages/pi-casefile/src/index.ts` (PromoteFinding), `src/poc-runner.ts`, `src/ledger.ts` (promoteFindingResult).
