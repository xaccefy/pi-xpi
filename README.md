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
| `PI_XP_MODE` | casefile | `on` / `off` — force casefile cyber-workflow injection |
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
| CaseAdd / CaseUpdate / PromoteFinding | Ledger + hard PoC gate to confirm |
| CaseGet / CaseList / CaseSearch | Browse cases |
| CaseLink / CaseUnlink | Exploit chains |
| CaseReport | Markdown report |
| PipelineSubmit | Stage-output validation gate: schema check + pre-filter + repair budget — stage can't advance on invalid output |
| ScratchpadInit / Resume / Checkpoint | Crash-recoverable artifact store for pipeline runs |
| ScratchpadWrite / Read / PhaseDone / Clear | Write, read, and resume pipeline artifacts |
| /casefile | Case dashboard |
| /xp | Toggle casefile **XP mode** (cyber workflow injection; **default OFF**) |
| todo / /todos | Multi-step task lists |
| fff (`ffgrep` / `fffind`) | Frecency-ranked file + content search; in `override` mode transparently upgrades pi's built-in `grep`/`find`. Installed by `install.sh`. |

## Quick start

```
/xp on                                      # enable casefile cyber workflow in context
```

Pi injects skill descriptions (`web-pentest`, `cyberwf`) into every session; the agent reads the full skill file when the task matches (e.g. "find bugs in X", "bug bounty Y"). Run `/xp on` for the full attacker discipline with casefile tracking.

## Skeptic + scratchpad

The pipeline has two mechanisms that keep findings honest:

- **Skeptic stage** — before a high-confidence finding reaches validation, a dedicated skeptic subagent independently re-reads the source (or re-probes the live endpoint) and tries to *disprove* it. If the skeptic finds a concrete reason the finding is false (a missed defense, an unreachable entry point, self-only impact), the finding is killed on the spot — no tie-breaker.
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
├── scripts/                 # bump-version, release
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

**Local release helper:**

```bash
bun run release:patch   # or release:minor / release:major
```

(Requires a clean tree and push rights. It commits, tags, and pushes but does NOT publish to npm — use the CI Release workflow for publishing.)
