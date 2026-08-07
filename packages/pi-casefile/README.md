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

Default DB path: `<workspace>/.pi/casefile.db`

## State machine

```
hypothesis → investigating → confirmed → reported
                 ↓               ↓
              blocked         killed (terminal)
```

- **investigating** needs `evidence` + `confidence`
- **confirmed** only by running the PoC (`PromoteFinding`, exit 0 + verification marker in output) — you can't just set status to confirmed. Promotion additionally requires an EvidenceAdd `observation` item (the initial signal) — the ledger rejects a `confirmed` with no evidence chain.
- **Live findings (`local:true`) also require `control_path`**: the same PoC run against a control lacking the vuln must NOT print the marker. The harness checks the control output itself — an unconditional-marker or mock-target PoC is blocked. The control run is stored as `controlVerified`. A control or disconfirmation script that **crashes** (killed / timeout / spawn error — no completion marker) is blocked too: a crash is not a clean control verdict and not a survived disproof. This applies at the ledger level, not just the tool: a local (sandbox:false) promotion without `controlVerification` is rejected by `promoteFindingResult` itself.
- **New cases require `disproveIf`** — falsification conditions (what would disprove this hypothesis). A hypothesis that can't say what kills it isn't one yet.
- **A kill must be justified**: either an EvidenceAdd `refutation` item, or a kill-reason token (intended_behavior, duplicate, framework_protection, out_of_scope, skeptic-disproven, no_attack_path, ...) in assumptions/nextStep. Bare `status: "killed"` is rejected.
- **reported** needs `CaseContext` first (records the report path; the report writer produces the final file)
- **killed** / **reported** are final (no more edits)

## Evidence items

`EvidenceAdd` records role-typed, artifact-backed evidence (observation / reproduction / impact / refutation / cleanup). Artifacts are stored as basename + SHA-256 — the full path is never persisted. The PoC gate auto-records the `reproduction` item (the PoC file, hashed) at promotion, so a confirmed case always traces back to a real artifact. `cleanup` items track engagement cleanup; record and confirm them before REPORT for sanctioned engagements (advisory — not yet a hard gate).

## Tools

| Tool | Use |
|------|-----|
| `CaseAdd` | Open a case (`title` + `disproveIf` required; start as `hypothesis` or `investigating`) |
| `CaseUpdate` | Evidence, impact, severity, status (not direct confirm) |
| `EvidenceAdd` | Role-typed, hashed evidence item on a case (refutation justifies kills; cleanup tracks cleanup) |
| `PromoteFinding` | Run on-disk PoC (Docker sandbox by default; `local:true` = host-network sandbox, host execution operator-gated via `PI_POC_ALLOW_LOCAL=1`) → confirm on exit 0 + marker; `control_path` + `control_liveness_marker` REQUIRED for every promotion |
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
