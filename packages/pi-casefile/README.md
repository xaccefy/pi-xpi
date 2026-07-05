# Casefile — Offensive Security Case Tracker

Track durable security cases during bug bounties, CTFs, and security audits.

## Surface Support

- **pi extension** — registers tools and `/casefile` dashboard.

## Tools (pi)

| pi | Description |
|---|---|
| **CaseAdd** | Open a new hypothesis or investigation |
| **CaseUpdate** | Update fields (status, evidence, impact, etc.) |
| **PromoteFinding** | **PoC Runner**: Verify PoC in Docker to confirm |
| **CaseGet** | Get full details of a single case |
| **CaseList** / **Search** | Browse or search across fields |
| **CaseLink** / **Unlink** | Connect primitives into exploit chains |
| **CaseReport** | Generate markdown report (confirmed/reported only) |

## PoC Runner (Docker / Local)

To promote a case from `investigating` to `confirmed`, you must use `PromoteFinding` with an on-disk PoC path.

- **Sandbox (Docker)**: Default. Runs in a `--network none` container with read-only mounts. Uses `python:3.12-slim` (.py) or `alpine` (.sh).
- **Local**: Use `local: true`. Runs directly on the host (e.g. for network-dependent bugs).
- **Verification**: Only promotes to `confirmed` if the PoC returns **exit code 0**.
- **Timeout**: 30 second limit.

## Offensive Security Workflow

1. **Hypothesize**: `CaseAdd(status: hypothesis)`
2. **Investigate**: `CaseUpdate(status: investigating, evidence, confidence)`
3. **Confirm**: `PromoteFinding(id, poc_path, local?)` -> Exit 0 verifies and confirms.
4. **Chain**: `CaseLink` primitives to escalations.
5. **Report**: `CaseReport` -> `CaseUpdate(status: reported)`.
6. **Kill**: `CaseUpdate(status: killed)` for dead ends.

### State Gates
- `hypothesis` → `investigating` requires `evidence` + `confidence`.
- `investigating` → `confirmed` requires a verified PoC run (exit 0) and `poc`, `evidence`, `impact`, `severity`.
- `confirmed` → `reported` requires `CaseReport` to have been generated.
- `killed` and `reported` are **terminal**.

## Storage & Environment

Stored as **SQLite** at `.casefile/casefile.db` (project) or `~/.casefile/casefile.db` (global).

- `CASEFILE_PATH`: Force exact ledger path.
- `CASEFILE_SCOPE=project|global`: Set storage scope.

## Project Structure

```
src/
  index.ts        — pi extension (tools, commands, events)
  ledger.ts       — SQLite storage engine
  poc-runner.ts   — Docker/local PoC verification
  sqlite-compat.ts — node:sqlite / bun:sqlite compat layer
skills/
  casefile/SKILL.md — agent skill prompt
test/
  ledger.test.ts   — unit tests
```

---
Install: `pi install npm:pi-casefile`

