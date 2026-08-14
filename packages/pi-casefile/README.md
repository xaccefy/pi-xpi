# pi-casefile

Local security case book for Pi Agent. Keeps your guesses → proven findings behind a PoC gate, saved in SQLite, run in a sandbox.

## Install

```bash
pi install npm:@xaccefy/pi-casefile
```

Or via the XPI umbrella package: `pi install npm:@xaccefy/pi-xpi`

## XP mode (default OFF)

The attack-mode text stays **quiet by default** so your normal coding isn't buried in security talk.

| Control | Effect |
|---------|--------|
| `/xp` | Toggle ON/OFF |
| `/xp on` / `/xp off` / `/xp lite` | Set explicitly |
| `PI_XP_MODE=on` | Force ON for this process (overrides file) |
| `PI_XP_MODE=lite` | Force LITE (single-agent, no subagent dispatch) |
| `PI_XP_MODE=off` | Force OFF |

When **ON**, every prompt gets the attacker-minded workflow plus any open cases. **LITE** is the same discipline done by the main agent alone — no `subagent` dispatch (CTF / single-shot engagements). When **OFF**, nothing is added; tools still work.

State is persisted next to the ledger as `xp-mode` (e.g. `.pi/xp-mode`).

## Environment

| Variable | Purpose |
|----------|---------|
| `PI_CASEFILE_PATH` | Absolute path to the SQLite ledger file |
| `CASEFILE_WORKSPACE_ROOT` / `PI_WORKSPACE_ROOT` | Override workspace root used to place `.pi/casefile.db` |
| `PI_POC_ALLOW_NETWORK=1` | Operator authorization for a networked PoC sandbox |
| `PI_POC_ALLOW_PRIVATE_REPLAY=1` | Operator authorization for harness replay to private/internal targets |
| `PI_POC_CONTROL_TARGETS` | Comma/newline-separated operator-approved control hosts/origins; agent-invented controls are rejected |

Default DB path: `<workspace>/.pi/casefile.db`

## State machine

```
hypothesis → investigating → confirmed → reported
                 ↓               ↓
              blocked         killed (terminal)
```

- **investigating** needs `evidence` + `confidence`
- **confirmed** only through the two-phase gate — `PromoteFinding` runs the PoC 2× target + 1× control, requires complete zero-exit runs and nonce-bound discriminating response-body evidence, then the harness performs a DNS-pinned identical replay and requires two conclusive responses with `target_only`. Reflection-capable requests may add a post-PoC harness-generated canary that must appear only on target. Status-only/trivial matchers and incomplete response capture are rejected. Exit zero is necessary but never proof. The main agent performs semantic review and calls `ConfirmFinding`, which captures a second fresh harness replay and binds it to the verdict; worker processes are rejected. Blind/OOB claims fail closed without a source-separated oracle.
- **Every promotion requires `control_path`** (the same bytes as the PoC — sha256 enforced) and a distinct `control_target` pre-approved by the operator in `PI_POC_CONTROL_TARGETS`; an agent cannot invent its own easy control. The control run is stored as `controlVerified`. Crashes, transport-inconclusive controls, status-only evidence, and missing evidence all block promotion.
- **New cases require `disproveIf`** — falsification conditions (what would disprove this hypothesis). A hypothesis that can't say what kills it isn't one yet.
- **A kill must be justified**: either an EvidenceAdd `refutation` item, or a canonical kill-reason token (intended_behavior, duplicate, framework_protection, out_of_scope, insufficient_impact, no_attack_path, ...) in assumptions/nextStep. Bare `status: "killed"` is rejected.
- **reported** needs `CaseContext` first (records the report path; the report writer produces the final file)
- **killed** / **reported** are final (no more edits)

## Evidence items

`EvidenceAdd` records role-typed, artifact-backed evidence (observation / reproduction / impact / refutation / cleanup). Artifact reads are restricted to regular, non-symlink files inside the workspace. Bytes are copied durably and stored as basename + SHA-256; the full source path is never persisted. The PoC gate auto-records the `reproduction` item at promotion.

## Tools

| Tool | Use |
|------|-----|
| `CaseAdd` | Open a case (`title` + `disproveIf` required; start as `hypothesis` or `investigating`) |
| `CaseUpdate` | Evidence, impact, severity, status (not direct confirm) |
| `EvidenceAdd` | Role-typed, hashed evidence item on a case (refutation justifies kills; cleanup tracks cleanup) |
| `PromoteFinding` | Phase 1: PoC 2× target + 1× operator-approved control, then DNS-pinned harness-owned replay requiring conclusive `target_only`; optional reflection canary upgrades the recorded proof strength when observed only on target. `local:true` and private replay are operator-gated; blind/OOB proof fails closed without source separation |
| `ConfirmFinding` | Phase 2: main-agent-only semantic decision plus a fresh harness-owned target/control replay (CONFIRMED promotes; NOT_CONFIRMED keeps investigating; worker calls are rejected) |
| `CaseGet` / `CaseList` / `CaseSearch` | Read / filter / search |
| `CaseLink` / `CaseUnlink` | Bidirectional exploit chains |
| `ChainSuggest` | Scan cases for exploitable chain combinations (credential+endpoint→ATO, redirect+OAuth→token theft, XSS+state-change→CSRF, IDOR+user-data, SSTI→RCE, race+payment, info-disclosure+SSRF), ranked by confidence |
| `CoverageAdd` | Record a tested (asset × attack-class) cell — `scope: wide` (deployment-wide verdict, applies to every later asset) or `local`; both found and clean results count. Optionally link the cell to an artifact-backed evidence item (`evidence_item_id`); unbacked cells render as ⚠ unbacked in the report |
| `CoverageReport` | Render the machine-checkable coverage matrix (which classes are tested where; plateau claims must match it) |
| `CaseContext` | Context bundle for a confirmed/reported case (full record, logs, links, artifacts) + report path |

Commands: `/casefile` (dashboard), `/xp` (XP mode).

## Development

```bash
bun test packages/pi-casefile
bun run typecheck
```
