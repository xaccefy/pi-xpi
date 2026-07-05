# pi-xtodo

`pi-xtodo` is a task manager and scheduler designed to structure agent workflows. It enforces task sequencing through acyclic dependency constraints and renders a real-time status overlay in the Pi Terminal User Interface (TUI).

## Features

- **Dependency Cycle Prevention**: Enforces a Directed Acyclic Graph (DAG) structure using Depth-First Search (DFS) topological validation.
- **TUI Integration**: Automatically positions a dynamic widget overlay (`aboveEditor` placement) containing active and pending tasks.
- **State Replay**: Restores session task states dynamically on start or branch traversal by parsing past tool executions from the session history.
- **Zod & TypeBox Validation**: Ensures strict parameter parsing for task operations.

## Installation

```bash
pi install npm:pi-xtodo
```

## Tool Specification: `todo`

The package registers the `todo` tool. Operations are executed through the `action` parameter:

### Actions

1. **`create`**: Instantiates a new task.
   - `subject` (string, required): Short summary of the task.
   - `description` (string, optional): Detailed explanation of steps.
   - `blockedBy` (array of numbers, optional): Initial IDs of tasks that must be completed first.
   - `owner` (string, optional): Associated agent.
2. **`update`**: Mutates fields of an existing task.
   - `id` (number, required): Target task ID.
   - `status` (string, optional): New state (`pending`, `in_progress`, `completed`, `deleted`).
   - `addBlockedBy` / `removeBlockedBy` (array of numbers, optional): Modify task dependencies.
3. **`list`**: Retrieves a filtered list of tasks.
   - `status` (string, optional): Filter by status.
   - `includeDeleted` (boolean, optional): Include tombstones.
4. **`get`**: Details a specific task, including forward and backward dependency links.
   - `id` (number, required): Task ID.
5. **`delete`**: Marks a task status as `deleted` (tombstone).
   - `id` (number, required): Task ID.
6. **`clear`**: Purges all task states from the active session.

## CLI Commands

- `/todos`: Interactive TUI slash command that outputs a grouped, formatted summary of all pending, in-progress, and completed tasks.
