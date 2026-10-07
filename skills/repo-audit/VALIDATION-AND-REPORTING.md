# VALIDATION AND REPORTING (coordinator, inline)

## Independent verification (fresh finding-verifier)

For each surviving candidate (post-tracer, post-skeptic), dispatch **finding-verifier** — never the auditor that authored it, never its skeptic. It re-reads source and checks the smallest decisive fact, returning `verified | contradicted | unverifiable | needs_runtime` per fact. You route:
- `contradicted` → kill the case with artifact-backed refutation evidence; write a `rejected` finding record (disproved claim + reason + evidence) so later runs do not resurrect it.
- `needs_runtime` → `needs_validation` record: exact claim, the single unresolved fact, and a `safe_local` or `owner_observed` resolution plan. No severity.
- `verified` → final record check.

## Final record check (you)

Before any `confirmed` record, re-verify against source and artifacts yourself: every `sourceTrace` path/line exists and says what the record claims; `observedResult` is bounded to what source analysis actually supports (no "attacker can..." beyond the demonstrated mechanism); conditions are real preconditions; severity is impact-based and consistent with the observed result; `smallestFix` addresses the root cause. The record checker (you) must be neither the candidate's author nor its coverage critic — dispatch the check to another fresh verifier pass if you authored the candidate.

Write `schemas/finding-record.schema.json` records (one per dispositioned finding) and validate each: `node scripts/validate-records.js <record.json>`. Records that do not validate are not reported. `confirmed` in source-audit mode uses `verification.mode: "static_only"` and the REPORT must label it source-verified, not exploited.

## Report (derived from records — never from memory)

Generate REPORT.md from the validated records + ledger only:
1. **Header** — run manifest summary: runId, revision, dirty state, mode, profile, harness, budget spent vs reserved.
2. **Coverage statement** — what the ledger covers, honestly: units by status, exclusions with reasons, deferred units with revisit triggers, and what this profile could not claim (`quick` ≠ full coverage; a narrow prior run is never full coverage).
3. **Findings** — one section per record, in severity order for `confirmed`, then `needs_validation` leads with their unresolved facts and resolution plans. Every claim in the report cites its record's evidence refs.
4. **Rejected leads** — one line each (fingerprint + reason) so the next run starts from knowledge, not zero.

No performance or discovery claim beyond what the records show. If the report says "all X were reviewed", the ledger must contain the units proving it.

## Close-out

- `ScratchpadPhaseDone` + checkpoint; CaseContext for each confirmed case.
- Update the manifest: `status: "completed"`, `ended` set — revalidate it.
- Suggest (do not auto-start) a follow-up `authorized_live` run for `needs_validation` records whose plans need it — that mode requires its own manifest, scope, and authorization record.
