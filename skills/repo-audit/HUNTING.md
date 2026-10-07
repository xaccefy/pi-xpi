# HUNTING (auditor rounds + coverage review)

## Hunt waves

Dispatch auditors in bounded batches (the cyberwf dispatch discipline applies: one batched call per wave, ≤3 auditors grouped by surface/family). Each auditor task names:
- the ledger unit IDs it owns,
- the class methodology files to read (`web-pentest/classes/<class>.md`),
- the requirement to return structured output (entry points analyzed, leads with file:line + disproveIf, per-unit coverage logs).

After each wave you (coordinator):
1. `PipelineSubmit` each auditor output; invalid output is a RETRY for that item, never a verdict.
2. Open `CaseAdd` (hypothesis, `disproveIf` required, no severity) for each surviving lead.
3. Update the ledger: units the wave actually covered get `reviewedPaths` + evidence-backed `checks` (case IDs count); `candidate` for units that produced leads; `blocked` with a reason when a unit needs something this mode lacks (runtime proof, credentials — route those to `needs_validation` leads instead of silently closing).

## Round loop

Waves re-hunt with accumulated intel (new surfaces from traces, new techniques from exploit_search). Between waves, TRACE (reachability) and SKEPTIC (disconfirmation, high-confidence leads only) run as in cyberwf. Stalled units follow the stall rule: 3 rounds without new signal → `deferred` with a concrete `revisitWhen`.

## Gate: COVERAGE REVIEW (fresh coverage-critic)

After the final wave (and at budget checkpoints in `deep` runs), dispatch **coverage-critic** with the manifest, recon map, and current ledger. It returns proposals (add/reopen/downgrade units) — it writes nothing.

You validate each proposal against source yourself, then either:
- update the ledger and dispatch one more bounded wave for the accepted units, or
- record the remainder as `deferred` with reasons (budget, scope).

Do not skip this gate: a hunt that was never reviewed has an untested coverage claim. Budget was reserved for it in the manifest.

**Exit criteria:** critic run; proposals dispositioned (ledger updated or deferrals recorded); every unit in a terminal status for this run; ledger validates.
