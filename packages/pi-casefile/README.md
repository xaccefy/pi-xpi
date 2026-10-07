# pi-casefile

Local security case book for Pi Agent. Guesses become findings only through a PoC gate. State lives in SQLite, PoCs run in a sandbox.

## Install

```bash
pi install npm:@xaccefy/pi-casefile
```

Or via the umbrella package: `pi install npm:@xaccefy/pi-xpi`

## XP mode (default OFF)

The attack-mode text stays quiet by default so normal coding isn't buried in security talk.

| Control | Effect |
|---------|--------|
| `/xp` | Toggle SWARM/OFF |
| `/xp on` | Default enabled mode: SWARM |
| `/xp swarm` | Bounded multi-agent workflow: auditor/tracer/skeptic/chain only |
| `/xp lite` | Single-agent, no subagent dispatch |
| `/xp off` | Quiet mode |
| `PI_XP_MODE=on` / `swarm` / `lite` / `off` | Force a mode for this process |

LITE runs everything in the main agent. SWARM delegates only auditor/tracer/skeptic/chain; validation, patching, reporting, and ConfirmFinding stay with the main agent. OFF adds nothing; tools still work. State persists as `xp-mode` next to the ledger.

## Environment

| Variable | Purpose |
|----------|---------|
| `PI_CASEFILE_PATH` | Absolute path to the SQLite ledger file |
| `CASEFILE_WORKSPACE_ROOT` / `PI_WORKSPACE_ROOT` | Workspace root used to place `.pi/casefile.db` |
| `PI_POC_ALLOW_NETWORK=1` | Operator authorization for a networked PoC sandbox |
| `PI_POC_ALLOW_PRIVATE_REPLAY=1` | Operator authorization for replay to private targets |
| `PI_POC_CONTROL_TARGETS` | Operator-approved control hosts; agent-invented controls are rejected |

Default DB path: `<workspace>/.pi/casefile.db`

## Case lifecycle

```
hypothesis → investigating → confirmed → reported
                 ↓               ↓
              blocked         killed (terminal)
```

- New cases need `disproveIf`: what evidence would kill the hypothesis. A hypothesis that can't say what kills it isn't one yet.
- `PromoteFinding` (phase 1, main agent only) runs the PoC twice on the target and once on an operator-approved control, requires zero-exit runs with nonce-bound response-body evidence, then replays the same request through the harness with DNS pinning and demands a `target_only` result. Access-control bugs use a same-host baseline instead of a control host. Status-only matchers and incomplete captures are rejected.
- `ConfirmFinding` (phase 2, main agent only) captures one more fresh replay and binds it to the semantic verdict. Worker processes are rejected on both phases.
- Kills need a refutation evidence item or a canonical kill reason. Bare `status: "killed"` is rejected.
- `reported` requires `CaseContext` first.

## Tools

| Tool | Use |
|------|-----|
| `CaseAdd` | Open a case (`title` + `disproveIf` required) |
| `CaseUpdate` | Evidence, impact, severity, status (no direct confirm) |
| `EvidenceAdd` | Role-typed, hashed evidence; refutation justifies kills |
| `PromoteFinding` | Phase 1 of the gate (see above) |
| `ConfirmFinding` | Phase 2 of the gate |
| `CaseGet` / `CaseList` / `CaseSearch` | Read / filter / search |
| `CaseLink` / `CaseUnlink` | Bidirectional exploit chains |
| `ChainSuggest` | Rank exploitable case combinations |
| `CoverageAdd` / `CoverageReport` | Record and render tested (asset × attack-class) cells |
| `CaseContext` | Full case bundle for the report |

Commands: `/casefile` (dashboard), `/xp` (XP mode).

## Development

```bash
bun test packages/pi-casefile
bun run typecheck
```
