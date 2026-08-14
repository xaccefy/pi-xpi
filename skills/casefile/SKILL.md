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
4. Mark `confirmed` only via the two-phase gate — main-agent `PromoteFinding` (PoC 2× target + 1× operator-approved control, nonce-bound body evidence, then a DNS-pinned conclusive `target_only` replay; use the post-PoC harness-generated canary for reflection-capable requests) → the main agent personally reviews → `ConfirmFinding`, which captures a fresh second harness replay before commit. Never delegate validation or confirmation; worker/subagent gate calls are rejected. Exit zero is run integrity, never vulnerability proof. A predicate differential is evidence, not an automatic exploit verdict. Blind/OOB findings remain investigating without a source-separated oracle.
5. Use CaseLink and CaseUnlink for exploit chains. Do not edit linked case IDs directly.
6. Use CaseContext only for confirmed or already reported cases: it writes the full context bundle (complete record, verification logs, links, pipeline artifacts) and records the report path. Then write the report and CaseUpdate status=`reported`.
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
- `PromoteFinding`: phase 1 — require a body predicate, bind the verify URL, pin DNS, and send the same request to target and an operator-approved `PI_POC_CONTROL_TARGETS` control. Both responses must be conclusive and only `target_only` passes. For reflection, place `{{PI_POC_CANARY}}` exactly once in the request and declare `verify.canary`; the harness creates the secret after the PoC exits and requires target-only reflection. Network/private access remains operator-gated; OOB fails closed without source separation.
- `ConfirmFinding`: phase 2 — main-agent-only review and fresh harness replay before commit (CONFIRMED promotes; NOT_CONFIRMED keeps investigating; worker/subagent calls are rejected). Record `canary_assessment=verified` when requested, otherwise `not_applicable` with a concrete reason.
- `CaseGet`: read one case by ID.
- `CaseList`: list cases with filters and pagination.
- `CaseSearch`: search all fields or a scoped field.
- `CaseLink`: bidirectionally link two cases.
- `CaseUnlink`: remove a bidirectional case link.
- `CaseContext`: write the case context bundle (complete record, PoC/disconfirmation logs, links, pipeline artifacts) for a confirmed or reported case and record the report path for the main agent.
