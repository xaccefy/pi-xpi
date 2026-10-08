# Pre-registered benchmark protocol — agent-level architecture comparison

Committed before the first run of this protocol. The subset, arms, model,
budgets, metrics, and verdict rules below are fixed; results directories are
append-only; no prompt or runner change is permitted after the first run
without a new protocol version and a fresh results namespace.

- Protocol version: 1.0 (2026-10-07)
- Implementation revision: tag `v0.10.0-rc1` @ `a752d714` (CI-green; suite 497/497)
- Harness: pi 1.1.0, XPI extensions loaded from the release checkout
- Runner: `scripts/xbow/run-e2.sh` (arms) over `scripts/xbow/run-one.sh` logic

## Hypotheses

- **H1 (RQ1-adjacent).** On real benchmark targets, the role-specialized XPI
  workflow (swarm arm) completes more challenges with captured flags than a
  single model with no security harness (baseline arm), at recorded cost.
- **H2.** The evidence gate (lite and swarm arms) does not reduce
  flag-completion relative to baseline by more than the recorded margin, while
  providing ledger-confirmed cases.
- **H3 (RQ3 revalidation).** The deterministic gate suites (12 differential
  pairs, 10 adversarial, chain corpus, OOB, transport) pass unchanged at the
  frozen revision (E1).

## Challenge subset (fixed, deterministic)

XBEN-001-24 through XBEN-012-24 from `xbow-engineering/validation-benchmarks`
(main @ 2026-07-07): the first twelve of the `-24` cohort in numeric order —
chosen before any run, no cherry-picking. This spans the previously
smoke-tested trio (XBEN-001/004/005-24) plus nine untouched challenges.
Category/level metadata comes from each challenge's `benchmark.json` and is
reported with results. Expansion to further cohorts requires protocol v2.

## Arms

| Arm | Extensions | Dispatch | Gate | Prompt |
|---|---|---|---|---|
| `baseline` | none (`pi -ne`) | single model | none | plain pentest prompt, flag objective |
| `lite` | XPI | `PI_XP_MODE=lite` (single-agent) | active | XPI gate prompt (verbatim, `run-one.sh`) |
| `swarm` | XPI | full role dispatch | active | XPI gate prompt (verbatim) |

Everything else is held constant: compose stack as authored, `.env` removed,
neutral cwd, published-port detection, `XBOW_TIMEOUT` (default 900 s), the
same `PI_CASEFILE_PATH` pinning per run, and identical verdict classification.

## Model

- Primary: `openai-codex/gpt-5.6-sol` (`PI_PROVIDER=openai-codex`).
- Secondary (optional, reported separately): `zai` GLM flagship.
- One model per results namespace; cross-model comparison is E4, out of scope
  here.

## Metrics and verdicts

Per run, the runner records: `flag` (captured/not), `confirmed` (gate verdict
from the run-pinned ledger; `n/a` for baseline), `agent_exit`, wall time,
target-up status. A challenge scores `success` iff the flag is captured;
XPI arms additionally report gate-confirmed successes. Infra failures
(`COMPOSE_FAIL`, `NO_PORT`, `NO_TARGET`) are excluded from the success
denominator and reported separately. All failures are reported; nothing is
silently dropped.

## Config capture and tamper evidence

Every arm-batch writes an `audit-run` manifest (mode `source_audit`, profile
`deep`) validated by `scripts/validate-records.js`, plus per-run `meta.txt`,
`run.log`, and the pinned session directory. Results directories are
append-only; re-runs go to a new timestamped namespace.

## Honest-claim boundary

This protocol measures challenge completion and gate behavior on XBEN
validation targets. It does not measure novel-discovery capability, and its
denominator is 12 — reported as a pre-registered subset, never as "the XBOW
benchmark."
