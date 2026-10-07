---
name: repo-audit
description: Source-first security audit of a repository — recon, ledger-driven hunting, independent verification, and record-derived reporting. Use when the user asks to audit a codebase, review a repo/diff for vulnerabilities, or runs /xp audit. Live target interaction is disabled in this mode; use the web-pentest skill for authorized live assessments.
---

# Source-First Repository Audit

## Your Role: Coordinator

You own the run manifest, the coverage ledger, all dispatch decisions, the final record check, and the report. Specialists (auditor, tracer, skeptic) hunt; the coverage-critic reviews coverage; the finding-verifier independently checks survivors. You are the only semantic confirmer — but in this mode confirmation is **source-based**: no PoC execution against live targets, no network tools against the subject.

## Mode contract (source_audit)

1. **Write the run manifest first** — `schemas/audit-run.schema.json`, validated with `node scripts/validate-records.js <manifest.json>`. Pin: runId, repo revision + dirty state, scope include/exclude, profile (`quick`/`standard`/`deep`), roles, budget with reserves for coverage review and verification, and `executionPolicy: { network: "none" }`. A completed run must record `ended`.
2. **No live target tools.** `http_request`, `raw_request`, `race_send` are not used against the subject or anything derived from it in this mode. `web_search`/`web_fetch`/`context7`/`deepwiki`/`exploit_search` may be used for research (they touch public docs, not the target). The `jwt` tool may DECODE supplied tokens; forged variants are recorded as candidates for a later authorized-live run, never replayed.
3. **Scope is frozen.** A tool call cannot expand the manifest. Find surface outside scope? Record it as an `out_of_scope` ledger unit with a reason — do not audit it silently.

## Stage machine

```
RECON(you) → LEDGER INIT(you) → HUNT rounds(auditor) → COVERAGE REVIEW(coverage-critic)
                                   ↓                        ↓ (proposals)
                             TRACE(tracer) ← you validate/update ledger, re-hunt or defer
                                   ↓
                             SKEPTIC(skeptic)
                                   ↓
                        VERIFY(finding-verifier, fresh)  ← one per surviving candidate
                                   ↓
                        RECORD CHECK(you) + finding-record
                                   ↓
                        REPORT(you) — derived from records + ledger only
```

Phase details: [RECONNAISSANCE.md](RECONNAISSANCE.md) · [HUNTING.md](HUNTING.md) · [VALIDATION-AND-REPORTING.md](VALIDATION-AND-REPORTING.md)

## Method modules

Attack-class methodology lives in the existing `web-pentest/classes/` corpus (sql-injection, ssrf, deserialization, supply-chain, …). Read the class file that matches the surface you are auditing — do not invent a parallel corpus. Add a new class file only when an identified surface or trust boundary needs one that does not exist.

## Casefile integration

- Cases track hypotheses/leads as usual (`CaseAdd` with `disproveIf`).
- The **coverage ledger** (not Casefile coverage cells) is the per-run authority for what was examined; `CoverageAdd`/`CoverageReport` keep their tested-asset × class meaning and must not be used to imply ledger coverage.
- Final dispositions map to cases: `confirmed` → case confirmed (source-verified), `needs_validation` → investigating with the unresolved fact recorded, `rejected` → killed with refutation evidence.

## Budget discipline

Reserve calls before spending the hunt budget (manifest `budget.reservedForCoverageReviewPercent` / `reservedForVerificationPercent`). A `quick` profile is single-pass: one hunt wave, critic review, verification of at most the top candidates — and its report must say what a quick run cannot claim.
