# pi-casefile

Local-first security case ledger for Pi Agent. Tracks hypotheses → confirmed findings with a hard PoC gate, SQLite storage, and an isolated PoC runner.

## Install

```bash
pi install npm:@xaccefy/pi-casefile
```

Or via the XPI umbrella package: `pi install npm:@xaccefy/pi-xpi`

## XP mode (default OFF)

The cyber-workflow context injection is **quiet by default** so normal dev work is not flooded with security process text.

| Control | Effect |
|---------|--------|
| `/xp` | Toggle ON/OFF |
| `/xp on` / `/xp off` | Set explicitly |
| `PI_XP_MODE=on` | Force ON for this process (overrides file) |
| `PI_XP_MODE=off` | Force OFF |

When **ON**, every prompt injects the attacker-oriented cyber workflow plus any active (non-killed/non-reported) cases. When **OFF**, nothing is injected; tools remain available.

State is persisted next to the ledger as `xp-mode` (e.g. `.pi/xp-mode`).

## Environment

| Variable | Purpose |
|----------|---------|
| `PI_CASEFILE_PATH` | Absolute path to the SQLite ledger file |
| `CASEFILE_WORKSPACE_ROOT` / `PI_WORKSPACE_ROOT` | Override workspace root used to place `.pi/casefile.db` |

Default DB path: `<workspace>/.pi/casefile.db`

## State machine

```
hypothesis → investigating → confirmed → reported
                 ↓               ↓
              blocked         killed (terminal)
```

- **investigating** requires `evidence` + `confidence`
- **confirmed** only via `PromoteFinding` (PoC exit 0) — `CaseUpdate(status:"confirmed")` is rejected
- **reported** requires `CaseReport` first
- **killed** / **reported** are terminal (no further field edits)

There is **no** `impact_proof` tool field. Put proof text in `impact` or `evidence`.

## Tools

| Tool | Use |
|------|-----|
| `CaseAdd` | Open a case (`title` required; start as `hypothesis` or `investigating`) |
| `CaseUpdate` | Evidence, impact, severity, status (not direct confirm) |
| `PromoteFinding` | Run on-disk PoC (Docker sandbox by default; `local:true` for host) → confirm on exit 0 |
| `CaseGet` / `CaseList` / `CaseSearch` | Read / filter / search |
| `CaseLink` / `CaseUnlink` | Bidirectional exploit chains |
| `CaseReport` | Markdown report for confirmed/reported cases |

Commands: `/casefile` (dashboard), `/xp` (XP mode).

## Development

```bash
bun test packages/pi-casefile
bun run typecheck
```
