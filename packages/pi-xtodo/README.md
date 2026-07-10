# pi-xtodo

Task list for multi-step agent work: DAG `blockedBy` dependencies, TUI overlay, session replay + disk fallback.

## Install

```bash
pi install npm:@xaccefy/pi-xtodo
```

## Tool: `todo`

| Action | Purpose |
|--------|---------|
| `create` | New task (`subject` required); optional `blockedBy`, `description`, `owner` |
| `update` | Mutate fields / status / dependencies (`id` required) |
| `list` | Filter by `status`; `includeDeleted` for tombstones |
| `get` | Full detail including blockedBy / blocks |
| `delete` | Soft-delete (tombstone) |
| `clear` | Wipe session task state |

### Status lifecycle

```
pending ↔ in_progress → completed → deleted
                ↘ deleted
```

- `completed → pending` is **not** allowed (use a new task if you need to reopen).
- Ids must be **positive integers** (string `"1"` is accepted; `"2.7"` / `"1e2"` are rejected).

### Dependencies

- `blockedBy` / `addBlockedBy` / `removeBlockedBy` form a DAG; cycles are rejected.
- **Deleting** a task (or `update status: deleted`) **scrubs** that id from every other task’s `blockedBy` so dependents are not stuck on tombstones.

### Persistence

- Primary source of truth: session tool-result history (replay on `session_start` / compact / tree).
- Fallback: `~/.pi/xtodo/<safe-session-id>.json` when branch history has no todo results yet.
- Session ids are sanitized so they cannot path-traverse out of that directory.

## Command

- `/todos` — grouped summary (interactive mode)

## Development

```bash
bun test packages/pi-xtodo
bun run typecheck
```
