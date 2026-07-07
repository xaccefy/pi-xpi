---
description: Start a security engagement (bug bounty / CTF / pentest) with the XPI evidence-first workflow
argument-hint: "<bugbounty|ctf|pentest> <target>"
---

Engagement type: {{$1}} — target: {{$2}}

Follow the XPI evidence-first doctrine: a claim is only real when a PoC on disk proves it. False positives are worse than misses.

## 0. Scope & rules (gate)
- Pull the authorized scope / out-of-scope list / prohibited techniques.
- If the target, endpoint, or technique is out of scope, stop.
- If authentication, credentials, or session cookies are required, **pause and ask the user** — never invent or borrow them.

## 1. Recon (research, don't guess)
- `ExploitSearch` for techniques mapped to the target's stack.
- `web_search` for CVEs / advisories / prior reports; `context7` / `deepwiki` for framework internals.

## 2. Hypothesis → case
- `CaseAdd(status: hypothesis, endpoint, bugClass, target)` per hypothesis, with the source→sink observation as `evidence`.
- `CaseList` / `CaseSearch` first to dedupe; `CaseLink` findings that chain.

## 3. Verify with a PoC (hard gate)
- Write the PoC on disk; run it via `PromoteFinding` (hardened runner — fails closed, never a false exit 0).
- **CONFIRMED requires** `evidence` + `poc` + `impact` + `severity` and a PoC `run.log` with **exit code 0**.
- If the PoC fails 3×, `CaseUpdate` the case to `killed` with the reason.

## 4. Report
- `CaseReport` after CONFIRMED, with repro steps another researcher can follow. Track dead ends as `killed`.

## Engagement-specific notes
- **bugbounty**: justify impact with a real C/I/A violation a **vendor would agree to** (data exposure / integrity change / DoS for others / financial). Check for duplicates before claiming.
- **ctf**: you're learning the primitive, not just grabbing the flag — document the exact technique per stage, save the flag + root cause in the case, and `CaseLink` multi-stage steps.
- **pentest**: stay within the rules of engagement; for lateral movement keep each foothold as its own case and prove real, client-acceptable impact.
