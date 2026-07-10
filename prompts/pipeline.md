---
description: Run a security pipeline (audit | harness | patch) against a target
argument-hint: "<audit|harness|patch> <target>"
---

Pipeline: {{$1}} — target: {{$2}}

- **audit** — Call `Agent` with `subagent_type: "auditor"` to scan for the requested vulnerability class / reachability path. Review candidates; open `CaseAdd(title: "<short title>", status: hypothesis)` per plausible one (dedupe via `CaseList` first).
- **harness** — Call `Agent` with `subagent_type: "harness"` to run the full VDH/VVS loop: auditor → exploit-dev (PoC via `PromoteFinding`, must exit 0) → patch-writer → `CaseReport`. Trust only findings with a PoC that exited 0.
- **patch** — Call `Agent` with `subagent_type: "patch-writer"` to remediate a confirmed finding, run `bun test` / `bun run typecheck`, and confirm the original PoC no longer exits 0.

Only trust findings the pipeline proves with a PoC that exited 0.
