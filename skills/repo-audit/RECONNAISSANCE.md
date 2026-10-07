# RECONNAISSANCE (coordinator, inline)

Produce the recon map the whole run works from. No dispatching yet.

## Inputs to pin

- Repo root, revision (commit SHA), dirty state + changed-file list. If the tree is dirty, the manifest records it; findings cite paths as-reviewed.
- Scope from the user (or manifest): included roots, excluded paths, and any authorization boundary. Source-audit needs no engagement authorization, but third-party code you were not asked to audit is still out of scope.

## Steps

1. **Inventory the surface.** Read manifests/package files first (dependency lists are the fastest trust-boundary map). Then enumerate entry points: route registrations, serverless handlers, CLI commands, queue consumers, webhooks, cron, file watchers, import-time side effects.
2. **Mark trust boundaries.** For each place data crosses a privilege/network line, note the boundary type: parser, deserializer, template engine, SQL/ORM boundary, exec/spawn, fetch/SSRF surface, authn/authz decision, crypto use, file access.
3. **Map lifecycle paths.** Install/migrate/provision/upgrade/teardown code — rarely exercised, rarely audited.
4. **Note deploy posture.** Dockerfiles, CI workflows, config defaults: what runs as root, what is world-readable, what defaults to insecure.
5. **Write the recon map** to the scratchpad (`ScratchpadInit` + `ScratchpadWrite`) as structured text the critic can re-read: surfaces, boundaries, lifecycle, dependencies, per-surface initial unit list.

## Gate: LEDGER INIT

Seed `schemas/coverage-ledger.schema.json` from the recon map:
- One unit per surface/boundary/class intersection worth its own review (`src/path.ts:boundary:class` IDs).
- Exclusions seeded as `out_of_scope` WITH reasons; the critic challenges unjustified ones.
- Everything else `planned`.

Validate: `node scripts/validate-records.js <ledger.json>`. A ledger that does not validate stops the run — fix it, never proceed on a malformed ledger.

**Exit criteria:** manifest written and validated; recon map checkpointed; seeded ledger validated; hunt wave planned (which units, which classes, which auditor batches).
