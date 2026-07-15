# XPI

Security tools for Pi Agent: casefile tracking, web search, library docs, exploit technique search, code intelligence, and todos.

## Install

Automate XPI plus third-party extension deps (`pi-codex-goal`, `pi-mcp-adapter`):

```bash
./install.sh
```

Or:

```bash
pi install npm:@xaccefy/pi-xpi
```

### API keys / env

| Variable | Package | Purpose |
|----------|---------|---------|
| `PREVIEW_IS_API_KEY` | exploitsearch | Required for `ExploitSearch` ([preview.is](https://preview.is)) |
| `PI_XP_MODE` | casefile | `on` / `off` — force casefile cyber-workflow injection |
| `PI_CASEFILE_PATH` | casefile | Override SQLite ledger path |
| `PI_WEBSEARCH_PORT` | lookup | open-websearch daemon port (default `3210`) |
| `PI_CHROMIUM_PATH` | lookup | Chromium binary for SPA re-render in `web_fetch` |

```bash
export PREVIEW_IS_API_KEY="rk_yourkeyhere"
```

## Tools

| Tool | Use for |
|------|---------|
| auth / /auth | Hold & use login sessions for targets (cookie, OAuth client-credentials, mTLS); **engage signup/login** to make a temp account on its own + prove it |
| ExploitSearch | Attack techniques, primitives, bypasses (`PREVIEW_IS_API_KEY`) |
| web_search | CVEs, advisories, documentation |
| web_fetch | Page content; SPA pages re-rendered via Chromium when the shell is thin |
| context7 | Current library docs |
| deepwiki | Q&A on a public GitHub repo |
| CaseAdd / CaseUpdate / PromoteFinding | Ledger + hard PoC gate to confirm |
| CaseGet / CaseList / CaseSearch | Browse cases |
| CaseLink / CaseUnlink | Exploit chains |
| CaseReport | Markdown report |
| /casefile | Case dashboard |
| /xp | Toggle casefile **XP mode** (cyber workflow injection; **default OFF**) |
| todo / /todos | Multi-step task lists |
| codebase-memory-mcp | Polyglot code indexer (158 languages). Tools: `index_repository`, `search_graph`, `trace_path`, `get_architecture`, `query_graph`. Installed by `install.sh` as an MCP server. |

## Quick start

```
/ops <bugbounty|ctf|pentest> <target>   # start an engagement
/pipeline <audit|harness|patch> <target>   # VDH/VVS discovery→validate→patch
/xp on                                      # enable casefile cyber workflow in context
```

Engagements and pipelines restate the workflow in the prompt body, so they work with XP mode off. Use `/xp on` when you want the full attacker discipline injected every turn.

## Code intelligence (codebase-memory-mcp)

XPI uses [codebase-memory-mcp](https://github.com/DeusData/codebase-memory-mcp) as its default code indexer. It's a single static binary that indexes **158 languages** via tree-sitter plus a Hybrid LSP type-resolution layer, exposing 14 MCP tools (`index_repository`, `search_graph`, `trace_path`, `get_architecture`, `query_graph`, `get_code_snippet`, …).

`install.sh` installs it as an MCP server alongside the in-process XPI extensions. For a readable target repo, index once with `index_repository`, then `get_architecture` for layout and `trace_path` to prove source→sink reachability — across Go, Solidity, Python, Rust, TS/JS, and 150+ others.

> The previous in-process `@xaccefy/pi-codeintel` package (TS/JS-only, TypeScript-compiler-based) was removed in favor of this polyglot backend. The agent falls back to `grep`/`read` when no indexer is available.

## Packages

| Package | npm |
|---------|-----|
| Umbrella | `@xaccefy/pi-xpi` |
| Auth sessions | `@xaccefy/pi-engage` |
| Case ledger | `@xaccefy/pi-casefile` |
| Lookup | `@xaccefy/pi-lookup` |
| Exploit search | `@xaccefy/pi-exploitsearch` |
| Todos | `@xaccefy/pi-xtodo` |

See each package’s `README.md` under `packages/*/`.

## Structure

```
pi-xpi/
├── prompts/                 # /ops, /pipeline
├── agents/                  # auditor, exploit-dev, patch-writer, harness
├── packages/
│   ├── pi-casefile
│   ├── pi-exploitsearch
│   ├── pi-lookup
│   ├── pi-engage
│   └── pi-xtodo
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

(Requires a clean tree, npm auth, and push rights.)

