# XPI Guide

Full reference: tools, configuration, pipeline, and development. The root [README](../README.md) is the short overview.

## Hosts: Pi Agent and OMP

XPI runs on **Pi Agent** (`@earendil-works/pi-coding-agent`) and its fork **OMP** (`@oh-my-pi/pi-coding-agent`, binary `omp`). The same extension code, tools, ledger, and XP-mode workflow are used on both:

- **Extensions** — both hosts read the `pi` field in `package.json` (OMP also accepts an `omp` field; `plugin.json` is the Agent Plugins manifest OMP uses for skills).
- **Skills** — `skills/cyberwf`, `skills/web-pentest`, `skills/casefile` load on both hosts (OMP via the Agent Plugins provider).
- **Subagent dispatch** — Pi uses the pi-subagents extension (`subagent({ workflowScript: ... })`); OMP uses its native `task` tool. The `/xp on` workflow and the `cyberwf` skill describe both conventions; the extension injects the host-appropriate workflow automatically.
- **Specialist agents** — `install.sh --omp` copies `agents/*.md` (auditor, tracer, skeptic, exploit, chain, reporter, confirmer) to `~/.omp/agent/agents` so OMP's `task` tool can spawn them by name. On Pi the same files ship inside the package for pi-subagents.

## Configuration

### Environment variables

| Variable | Package | Purpose |
|----------|---------|---------|
| `PREVIEW_IS_API_KEY` | webxp | Required for `exploit_search` ([preview.is](https://preview.is)) |
| `PI_XP_MODE` | casefile | `on` / `lite` / `off` — force casefile cyber-workflow injection (lite = single-agent, no subagent dispatch) |
| `PI_CASEFILE_PATH` | casefile | Override SQLite ledger path |
| `PI_WEBSEARCH_PORT` | webxp | open-websearch daemon port (default `3210`) |
| `PI_FFF_MODE` | fff | `override` replaces pi's built-in grep/find with fff (set in your shell profile; Pi only — OMP ships its own search) |

```bash
export PREVIEW_IS_API_KEY="rk_yourkeyhere"
```

## Tools

| Tool | Use for |
|------|---------|
| `exploit_search` | Attack techniques, primitives, bypasses (`PREVIEW_IS_API_KEY`) |
| `web_search` | CVEs, advisories, documentation |
| `web_fetch` | Page content from an HTTP(S) URL |
| `context7` | Current library docs |
| `deepwiki` | Q&A on a public GitHub repo |
| `CaseAdd` / `CaseUpdate` / `PromoteFinding` / `ConfirmFinding` | Ledger + two-phase PoC gate to confirm: PromoteFinding records an evidence bundle (PoC 2× target + 1× same-script control; every run must complete with captured output and write nonce-bound `evidence.json`; machine-checks nonce binding, determinism, target/control differential), then a confirmer subagent re-executes the verify request and its CONFIRMED verdict (via ConfirmFinding) promotes. Markers/exit codes are diagnostics, not gates |
| `EvidenceAdd` | Role-typed, hashed evidence items (observation/reproduction/impact/refutation/cleanup); refutation justifies kills; reproduction auto-recorded by the PoC gate |
| `CaseGet` / `CaseList` / `CaseSearch` | Browse cases |
| `CaseLink` / `CaseUnlink` | Exploit chains |
| `ChainSuggest` | Auto-detect exploitable chain combinations across cases (credential+endpoint→ATO, XSS+state-change→CSRF, SSTI→RCE, race+payment, …), ranked — verify before linking |
| `CoverageAdd` / `CoverageReport` | Machine-checkable test coverage: record (asset × attack-class) cells with wide/local scope, linked to artifact-backed evidence items (`evidence_item_id`); unbacked cells render as ⚠ unbacked, and the plateau claim must match the matrix |
| `CaseContext` | Case context bundle (complete record + artifacts) for the report writer |
| `PipelineSubmit` | Stage-output validation gate: schema check + pre-filter + repair budget — stage can't advance on invalid output |
| `ScratchpadInit` / `Resume` / `Checkpoint` | Crash-recoverable artifact store for pipeline runs |
| `ScratchpadWrite` / `Read` / `PhaseDone` / `Clear` | Write, read, and resume pipeline artifacts |
| `/casefile` | Case dashboard |
| `/xp` | Toggle casefile **XP mode** (cyber workflow injection; `on` = subagent pipeline, `lite` = single-agent, **default OFF**) |
| `todo` / `/todos` | Multi-step task lists |
| `ffgrep` / `fffind` | Frecency-ranked file + content search; in `override` mode transparently upgrades pi's built-in `grep`/`find`. Installed by `install.sh`. |

## Quick start

```
/xp on                                      # enable casefile cyber workflow in context
/xp lite                                    # single-agent variant — no subagent dispatch
```

CaseAdd requires `disproveIf` (falsification conditions) on every new case; a kill of a case that ever reached investigating/confirmed requires artifact-backed refutation evidence (a keyword alone is not enough, and demoting the status first does not reset that). Confirmation is two-phase: **PromoteFinding** runs the PoC twice against the case target plus once against a distinct `control_target` (same script, sha256-enforced); every run must complete with fully captured output and write nonce-bound `evidence.json` to `$PI_POC_EVIDENCE_DIR`; the machine gate then checks nonce binding, determinism across the two target runs, and that the control evidence differs from the target's (not target-dependent → blocked). The coordinator dispatches the **confirmer** subagent (fresh context, different model), which re-sends the `verify` request itself and returns a verdict; **ConfirmFinding** commits it — CONFIRMED (requires `re_executed: true`, a `target_only` differential, and the confirmer's own `disconfirmation_attempt`) promotes, NOT_CONFIRMED keeps the case investigating. Exit codes and output markers are diagnostics, not gates. `local:true` runs in a host-network Docker sandbox (read-only FS / dropped caps / unprivileged user); true host execution is operator-gated via `PI_POC_ALLOW_LOCAL=1` and is never agent-selectable. Promotion also requires an **artifact-backed** `observation` evidence item (EvidenceAdd with `artifact_path` — summary-only observations are rejected)

Pi injects skill descriptions (`web-pentest`, `cyberwf`) into every session; the agent reads the full skill file when the task matches (e.g. "find bugs in X", "bug bounty Y"). Run `/xp on` for the full attacker discipline with casefile tracking, or `/xp lite` for the same discipline done by the main agent alone (CTF / single-shot engagements).

## Skeptic + scratchpad — how findings stay honest

The pipeline has two mechanisms that keep findings honest:

- **Skeptic stage** — before a high-confidence finding reaches validation, a dedicated skeptic subagent independently re-reads the source (or re-probes the live endpoint) and tries to *disprove* it. If the skeptic finds a concrete reason the finding is false (a missed defense, an unreachable entry point, self-only impact), the finding is killed on the spot — no tie-breaker.
- **Design & runtime check** — before CONFIRMED, every finding must survive a search for the design decision: docs/README, git history, changelog, and whether the runtime/framework version already mitigates the path. Documented intent → kill `intended_behavior`; runtime already blocks it → kill `framework_protection`; neither → the search notes become the non-intentionality evidence the report needs.
- **Scratchpad** — a crash-recoverable artifact store. Each pipeline phase writes its intermediate output (recon maps, trace outputs, verification logs) to `.scratchpad/{run_id}/` instead of stuffing everything into casefile text fields. If a run crashes mid-pipeline, resume picks up from the last checkpoint without re-running completed phases.

See `skills/cyberwf/SKILL.md` for the full stage machine and API.

## Code search (fff)

XPI uses [fff](https://github.com/dmtrKovalenko/fff) (`@ff-labs/pi-fff`) for file and content search — a frecency-ranked, typo-tolerant engine that runs as a native Pi extension, no separate MCP process.

`install.sh` installs it; add `export PI_FFF_MODE=override` to your shell profile (install.sh reminds you — an executed script can't export for you). Override mode transparently replaces pi's built-in `grep`/`find`/`multi_grep` with fff's implementations. The agent's existing `grep`/`find` calls get faster and smarter with no prompt or skill changes — `ffgrep` auto-detects regex vs fuzzy, `fffind` matches whole repo-relative paths and ranks by frecency.

For a target repo, the auditor and tracer agents lean on `grep`/`find`/`read` to locate sinks, entry points, and call chains. fff keeps those searches accurate across large codebases without a heavy index step.

## Structure

```
pi-xpi/
├── agents/                  # auditor, tracer, exploit, chain, skeptic
├── packages/
│   ├── pi-casefile          # ledger, poc-runner, workflow, scratchpad
│   ├── pi-shared
│   ├── pi-webxp
│   └── pi-xtodo
├── schemas/                 # stage-finding, stage-trace, stage-skeptic, stage-validation, stage-chain, stage-report
├── scripts/                 # bump-version
├── skills/                  # web-pentest, cyberwf (auto-loaded)
├── install.sh
└── package.json
```

## Develop & release

```bash
bun install
bun test --isolate
bun run typecheck
```

**Release (CI):** GitHub Actions → **Release** workflow → choose `patch` / `minor` / `major`.
Requires repo secret `NPM_TOKEN`. The job runs tests, bumps all workspace versions, publishes every package + umbrella, tags `vX.Y.Z`, and pushes.
