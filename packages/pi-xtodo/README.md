# pi-xtodo

Task list for step-by-step agent work: `blockedBy` links (a DAG), TUI overlay, replay from history or save to disk.

## Install

```bash
pi install npm:@xaccefy/pi-xtodo
```

## Tool: `todo`

| Action | Purpose |
|--------|---------|
| `create` | New task (`subject` needed); optional `blockedBy`, `description`, `owner` |
| `update` | Change fields / status / links (`id` needed) |
| `list` | Filter by `status`; `includeDeleted` for tombstones |
| `get` | Full detail including blockedBy / blocks |
| `delete` | Soft-delete (kept as a tombstone) |
| `clear` | Clear all tasks |

### Status lifecycle

```
pending ↔ in_progress → completed → deleted
                ↘ deleted
```

- `completed → pending` is **not** allowed (make a new task to reopen).
- Ids must be **whole positive numbers** (`"1"` works; `"2.7"` / `"1e2"` are rejected).

### Dependencies

- `blockedBy` / `addBlockedBy` / `removeBlockedBy` form a DAG; cycles are rejected.
- **Deleting** a task (or `update status: deleted`) **pulls** its id out of every other task’s `blockedBy`, so dependents don’t hang on a tombstone.

### Persistence

- Main copy: the session’s tool-result history (replay on `session_start` / compact / tree).
- If that’s empty, use the disk file `~/.pi/xtodo/<safe-session-id>.json`.
- Session ids are cleaned so they can’t escape the folder.

## Display

- Tool results render as a one-line summary (glyph + first line / task count).
  Expand the tool row (`app.tools.expand` keybinding) to see full lists and details.
  Errors render as `✗ <message>`.

## Command

- `/todos` — overlay with the full list, grouped active → completed → deleted
  (`esc`/`q`/`enter` closes). Falls back to a notification when overlays are
  unavailable.

## Development

```bash
bun test packages/pi-xtodo
bun run typecheck
```
