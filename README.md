# XPI

Security tooling for the Pi agent — casefile tracking, web search, library docs, exploit-technique search, code intelligence, and todos. Built to give an agent a real attacker workflow instead of ad-hoc prompting.

## Install

The easy way — pulls in XPI plus its third-party extension deps (`pi-codex-goal`, `pi-mcp-adapter`):

```bash
./install.sh
```

Or install the umbrella package directly:

```bash
pi install npm:@xaccefy/pi-xpi
```

### API keys / env

| Variable | Package | Purpose |
|----------|---------|---------|
| `PREVIEW_IS_API_KEY` | webxp | Required for `exploit_search` ([preview.is](https://preview.is)) |
| `PI_XP_MODE` | casefile | `on` / `lite` / `off` — force casefile cyber-workflow injection (lite = single-agent, no subagent dispatch) |
| `PI_CASEFILE_PATH` | casefile | Override SQLite ledger path |
| `PI_WEBSEARCH_PORT` | webxp | open-websearch daemon port (default `3210`) |
| `PI_CHROMIUM_PATH` | webxp | Chromium binary for SPA re-render in `web_fetch` |
| `PI_FFF_MODE` | fff | `override` replaces pi's built-in grep/find with fff (set in your shell profile) |

```bash
export PREVIEW_IS_API_KEY="rk_yourkeyhere"
```

## Tools

| Tool | Use for |
|------|---------|
| exploit_search | Attack techniques, primitives, bypasses (`PREVIEW_IS_API_KEY`) |
| web_search | CVEs, advisories, documentation |
| web_fetch | Page content; SPA pages re-rendered via Chromium when the shell is thin |
| context7 | Current library docs |
| deepwiki | Q&A on a public GitHub repo |
| CaseAdd / CaseUpdate / PromoteFinding | Ledger + hard PoC gate to confirm (exit 0 + verification marker; `control_path` control-target check required for live findings — blocks unconditional-marker/mock PoCs) |
| EvidenceAdd | Role-typed, hashed evidence items (observation/reproduction/impact/refutation/cleanup); refutation justifies kills; reproduction auto-recorded by the PoC gate |
| CaseGet / CaseList / CaseSearch | Browse cases |
| CaseLink / CaseUnlink | Exploit chains |
| ChainSuggest | Auto-detect exploitable chain combinations across cases (credential+endpoint→ATO, XSS+state-change→CSRF, SSTI→RCE, race+payment, …), ranked — verify before linking |
| CoverageAdd / CoverageReport | Machine-checkable test coverage: record (asset × attack-class) cells with wide/local scope; the plateau claim must match the matrix |
| CaseContext | Case context bundle (complete record + artifacts) for the report writer |
| PipelineSubmit | Stage-output validation gate: schema check + pre-filter + repair budget — stage can't advance on invalid output |
| ScratchpadInit / Resume / Checkpoint | Crash-recoverable artifact store for pipeline runs |
| ScratchpadWrite / Read / PhaseDone / Clear | Write, read, and resume pipeline artifacts |
| /casefile | Case dashboard |
| /xp | Toggle casefile **XP mode** (cyber workflow injection; `on` = subagent pipeline, `lite` = single-agent, **default OFF**) |
| todo / /todos | Multi-step task lists |
| fff (`ffgrep` / `fffind`) | Frecency-ranked file + content search; in `override` mode transparently upgrades pi's built-in `grep`/`find`. Installed by `install.sh`. |

## Quick start

```
/xp on                                      # enable casefile cyber workflow in context
/xp lite                                    # single-agent variant — no subagent dispatch
```

CaseAdd requires `disproveIf` (falsification conditions) on every new case; a kill requires refutation evidence or a kill-reason token; live findings (`local:true`) require a `control_path` control run whose output must NOT contain the verification marker (harness-checked). Promotion also requires an `observation` evidence item (EvidenceAdd) before `confirmed`, and control/disconfirmation scripts that crash (killed/timeout/spawn error) are blocked — a crash is neither a clean control verdict nor a survived disproof.

Pi injects skill descriptions (`web-pentest`, `cyberwf`) into every session; the agent reads the full skill file when the task matches (e.g. "find bugs in X", "bug bounty Y"). Run `/xp on` for the full attacker discipline with casefile tracking, or `/xp lite` for the same discipline done by the main agent alone (CTF / single-shot engagements).

## Skeptic + scratchpad

The pipeline has two mechanisms that keep findings honest:

- **Skeptic stage** — before a high-confidence finding reaches validation, a dedicated skeptic subagent independently re-reads the source (or re-probes the live endpoint) and tries to *disprove* it. If the skeptic finds a concrete reason the finding is false (a missed defense, an unreachable entry point, self-only impact), the finding is killed on the spot — no tie-breaker.
- **Design & runtime check** — before CONFIRMED, every finding must survive a search for the design decision: docs/README, git history, changelog, and whether the runtime/framework version already mitigates the path. Documented intent → kill `intended_behavior`; runtime already blocks it → kill `framework_protection`; neither → the search notes become the non-intentionality evidence the report needs.
- **Scratchpad** — a crash-recoverable artifact store. Each pipeline phase writes its intermediate output (recon maps, trace outputs, verification logs) to `.scratchpad/{run_id}/` instead of stuffing everything into casefile text fields. If a run crashes mid-pipeline, resume picks up from the last checkpoint without re-running completed phases.

See `skills/cyberwf/SKILL.md` for the full stage machine and API.

## Code search (fff)

XPI uses [fff](https://github.com/dmtrKovalenko/fff) (`@ff-labs/pi-fff`) for file and content search — a frecency-ranked, typo-tolerant engine that runs as a native Pi extension, no separate MCP process.

`install.sh` installs it; add `export PI_FFF_MODE=override` to your shell profile (install.sh reminds you — an executed script can't export for you). Override mode transparently replaces pi's built-in `grep`/`find`/`multi_grep` with fff's implementations. The agent's existing `grep`/`find` calls get faster and smarter with no prompt or skill changes — `ffgrep` auto-detects regex vs fuzzy, `fffind` matches whole repo-relative paths and ranks by frecency.

For a target repo, the auditor and tracer agents lean on `grep`/`find`/`read` to locate sinks, entry points, and call chains. fff keeps those searches accurate across large codebases without a heavy index step.

## Packages

| Package | npm |
|---------|-----|
| Umbrella | `@xaccefy/pi-xpi` |
| Case ledger | `@xaccefy/pi-casefile` |
| Web lookup + exploit search | `@xaccefy/pi-webxp` |
| Todos | `@xaccefy/pi-xtodo` |

See each package's `README.md` under `packages/*/`.

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

## Develop / release

```bash
bun install
bun test --isolate
bun run typecheck
```

**Release (CI):** GitHub Actions → **Release** workflow → choose `patch` / `minor` / `major`.
Requires repo secret `NPM_TOKEN`. The job runs tests, bumps all workspace versions, publishes every package + umbrella, tags `vX.Y.Z`, and pushes.
