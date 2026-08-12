---
name: casefile
description: Use when tracking security investigations, bug bounty findings, CTF leads, audit evidence, exploit chains, dead ends, or reports in the Casefile ledger.
license: MIT
---

<!-- Mirror of packages/pi-casefile/skills/casefile/SKILL.md — keep both in sync. -->

# Casefile Tracker

Use Casefile to maintain durable security investigation state across agent turns.

## Workflow

1. Check existing cases before opening a new one with CaseList or CaseSearch.
2. Open new leads with CaseAdd as `hypothesis` or `investigating`.
3. Promote cases with CaseUpdate only after materially new evidence, proof, impact, blockers, remediation, or status changes.
4. Mark `confirmed` only via the two-phase gate — `PromoteFinding` (runs the PoC 2× against the target + 1× against a distinct control target; every run must write nonce-bound `evidence.json` and complete with captured output) → dispatch the `confirmer` subagent → commit its verdict with `ConfirmFinding`. Markers and exit codes are diagnostics, not gates.
5. Use CaseLink and CaseUnlink for exploit chains. Do not edit linked case IDs directly.
6. Use CaseContext only for confirmed or already reported cases: it writes the full context bundle (complete record, verification logs, links, pipeline artifacts) and records the report path. Then have the report written (reporter agent in the full pipeline; yourself in lite mode) and CaseUpdate status=`reported`.
7. Use `killed` for disproven, duplicate, or dead-end leads, and include evidence, blockers, next step, or assumptions explaining why.

## State machine

```
hypothesis → investigating → confirmed → reported
                 ↓               ↓
              blocked         killed (terminal)
```

- investigating requires evidence + confidence
- confirmed requires PromoteFinding + ConfirmFinding (never CaseUpdate)
- killed/reported are terminal (no field edits or re-links)

## Tool Map

- `CaseAdd`: create a new case.
- `CaseUpdate`: update an existing case.
- `PromoteFinding`: phase 1 of confirmation — run an on-disk PoC script (Docker sandbox or local) against the target 2× plus a same-script control run; machine-validates nonce-bound evidence.json, determinism, and the target/control differential; records a 1h pending bundle and returns the confirmer dispatch instruction.
- `ConfirmFinding`: phase 2 — commit the confirmer's verdict (CONFIRMED promotes to confirmed; NOT_CONFIRMED keeps investigating, no tie-breaker).
- `CaseGet`: read one case by ID.
- `CaseList`: list cases with filters and pagination.
- `CaseSearch`: search all fields or a scoped field.
- `CaseLink`: bidirectionally link two cases.
- `CaseUnlink`: remove a bidirectional case link.
- `CaseContext`: write the case context bundle (complete record, PoC/disconfirmation logs, links, pipeline artifacts) for a confirmed or reported case and record the report path for the report writer.
