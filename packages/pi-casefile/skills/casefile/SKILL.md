---
name: casefile
description: Use when tracking security investigations, bug bounty findings, CTF leads, audit evidence, exploit chains, dead ends, or reports in the Casefile ledger.
license: MIT
---

# Casefile Tracker

Use Casefile to maintain durable security investigation state across agent turns.

## Workflow

1. Check existing cases before opening a new one with CaseList or CaseSearch.
2. Open new leads with CaseAdd as `hypothesis` or `investigating`.
3. Promote cases with CaseUpdate only after materially new evidence, proof, impact, blockers, remediation, or status changes.
4. Mark `confirmed` only via PromoteFinding after a real PoC exit 0 (evidence, impact, severity, poc required).
5. Use CaseLink and CaseUnlink for exploit chains. Do not edit linked case IDs directly.
6. Use CaseReport only for confirmed or already reported cases, then CaseUpdate status=`reported`.
7. Use `killed` for disproven, duplicate, or dead-end leads, and include evidence, blockers, next step, or assumptions explaining why.

## State machine

```
hypothesis → investigating → confirmed → reported
                 ↓               ↓
              blocked         killed (terminal)
```

- investigating requires evidence + confidence
- confirmed requires PromoteFinding (not CaseUpdate)
- killed/reported are terminal (no field edits or re-links)

## Tool Map

- `CaseAdd`: create a new case.
- `CaseUpdate`: update an existing case.
- `PromoteFinding`: run an on-disk PoC script (Docker sandbox or local) and promote a case to confirmed on exit 0.
- `CaseGet`: read one case by ID.
- `CaseList`: list cases with filters and pagination.
- `CaseSearch`: search all fields or a scoped field.
- `CaseLink`: bidirectionally link two cases.
- `CaseUnlink`: remove a bidirectional case link.
- `CaseReport`: write a markdown report for a confirmed or reported case.
