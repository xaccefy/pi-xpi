import assert from "node:assert";
import { unlinkSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { beforeEach, describe, it } from "node:test";
import { MockExtensionAPI } from "../../../test-utils.ts";
import { __replayComputeCount, __resetState, default as registerTodo } from "../index.ts";

class MockSessionManager {
  sessionId = "test-session";
  branch: any[] = [];
  getSessionId() {
    return this.sessionId;
  }
  getBranch() {
    return this.branch;
  }
}

describe("pi-xtodo simplified tests", () => {
  let pi: MockExtensionAPI;
  let sessionManager: MockSessionManager;
  let mockCtx: any;

  beforeEach(() => {
    __resetState();
    pi = new MockExtensionAPI();
    registerTodo(pi as any);
    sessionManager = new MockSessionManager();
    mockCtx = { sessionManager };
  });

  it("should register todo tool and todos command", () => {
    assert.strictEqual(pi.tools.length, 1);
    assert.strictEqual(pi.tools[0].name, "todo");
    assert.ok(pi.commands.todos);
  });

  it("create, update, delete, list flow", async () => {
    const todoTool = pi.tools[0];

    // 1. Create a task
    const createResult = await todoTool.execute(
      "1",
      { action: "create", subject: "Write testing suite" },
      null,
      null,
      mockCtx,
    );
    assert.ok(createResult.content[0].text.includes("Created #1: Write testing suite (pending)"));
    assert.strictEqual(createResult.details.tasks.length, 1);
    assert.strictEqual(createResult.details.tasks[0].id, 1);
    assert.strictEqual(createResult.details.tasks[0].status, "pending");

    // 2. Perform legal updates
    const update1 = await todoTool.execute(
      "3",
      { action: "update", id: 1, status: "in_progress", activeForm: "writing unit tests" },
      null,
      null,
      mockCtx,
    );
    assert.ok(update1.content[0].text.includes("Updated #1 (pending → in_progress)"));

    const update2 = await todoTool.execute(
      "4",
      { action: "update", id: 1, status: "completed" },
      null,
      null,
      mockCtx,
    );
    assert.ok(update2.content[0].text.includes("Updated #1 (in_progress → completed)"));

    // 3. Try illegal update (completed -> in_progress)
    const badUpdate = await todoTool.execute(
      "2",
      { action: "update", id: 1, status: "in_progress" },
      null,
      null,
      mockCtx,
    );
    assert.ok(
      badUpdate.content[0].text.includes("Error: illegal transition completed → in_progress"),
    );

    // 4. List tasks
    const listResult = await todoTool.execute("5", { action: "list" }, null, null, mockCtx);
    assert.ok(listResult.content[0].text.includes("[completed] #1 Write testing suite"));

    // 5. Delete task
    const deleteResult = await todoTool.execute(
      "6",
      { action: "delete", id: 1 },
      null,
      null,
      mockCtx,
    );
    assert.ok(deleteResult.content[0].text.includes("Deleted #1: Write testing suite"));

    // 6. List returns no tasks (since deleted)
    const listEmpty = await todoTool.execute("7", { action: "list" }, null, null, mockCtx);
    assert.strictEqual(listEmpty.content[0].text, "No tasks");
  });

  it("blockedBy cycle detection", async () => {
    const todoTool = pi.tools[0];

    await todoTool.execute("1", { action: "create", subject: "Task A" }, null, null, mockCtx);
    await todoTool.execute("2", { action: "create", subject: "Task B" }, null, null, mockCtx);

    // Block Task B on Task A
    await todoTool.execute(
      "3",
      { action: "update", id: 2, addBlockedBy: [1] },
      null,
      null,
      mockCtx,
    );

    // Try to block Task A on Task B (creates cycle B -> A -> B)
    const badCycle = await todoTool.execute(
      "4",
      { action: "update", id: 1, addBlockedBy: [2] },
      null,
      null,
      mockCtx,
    );
    assert.ok(badCycle.content[0].text.includes("Error: addBlockedBy would create a cycle"));
  });

  it("replayFromBranch state reconstruction", async () => {
    const todoTool = pi.tools[0];

    // Execute some tasks
    await todoTool.execute("1", { action: "create", subject: "Task 1" }, null, null, mockCtx);
    const lastResult = await todoTool.execute(
      "2",
      { action: "create", subject: "Task 2" },
      null,
      null,
      mockCtx,
    );

    // Simulate session manager history
    sessionManager.branch = [
      {
        type: "message",
        message: {
          role: "toolResult",
          toolName: "todo",
          details: lastResult.details,
        },
      },
    ];

    // Emit session_start to trigger replay
    await pi.emit("session_start", {}, mockCtx);

    // Verify state is restored
    const listResult = await todoTool.execute("3", { action: "list" }, null, null, mockCtx);
    assert.ok(listResult.content[0].text.includes("#1 Task 1"));
    assert.ok(listResult.content[0].text.includes("#2 Task 2"));
  });

  it("persists tasks to disk and restores them on session_start when branch history is empty", async () => {
    sessionManager.sessionId = "persist-test-session";
    sessionManager.branch = [];
    const todoTool = pi.tools[0];

    await todoTool.execute(
      "1",
      { action: "create", subject: "Persisted task" },
      null,
      null,
      mockCtx,
    );

    // Simulate a restart: fresh branch (no todo history) but the saved file exists.
    sessionManager.branch = [];
    await pi.emit("session_start", {}, mockCtx);

    const listResult = await todoTool.execute("2", { action: "list" }, null, null, mockCtx);
    assert.ok(listResult.content[0].text.includes("#1 Persisted task"));

    // Clean up the persisted file for this isolated session id.
    try {
      unlinkSync(join(homedir(), ".pi", "xtodo", "persist-test-session.json"));
    } catch {
      // File may not exist.
    }
  });

  it("skips replay when branch length is unchanged (cache hit, no recompute)", async () => {
    const todoTool = pi.tools[0];
    sessionManager.sessionId = "cache-skip-session";
    sessionManager.branch = [];

    // Seed a branch history containing one create result.
    const created = await todoTool.execute(
      "1",
      { action: "create", subject: "Cache task" },
      null,
      null,
      mockCtx,
    );
    sessionManager.branch = [
      {
        type: "message",
        message: {
          role: "toolResult",
          toolName: "todo",
          details: created.details,
        },
      },
    ];

    await pi.emit("session_start", {}, mockCtx);
    assert.strictEqual(__replayComputeCount(), 1);

    // Same branch length -> cache hit, must NOT recompute.
    await pi.emit("session_start", {}, mockCtx);
    assert.strictEqual(__replayComputeCount(), 1);

    // Different branch length -> cache miss -> recompute.
    sessionManager.branch = [
      ...sessionManager.branch,
      { type: "message", message: { role: "assistant", content: "more" } },
    ];
    await pi.emit("session_start", {}, mockCtx);
    assert.strictEqual(__replayComputeCount(), 2);
  });
});
