import assert from "node:assert";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, beforeEach, describe, it } from "node:test";
import { MockExtensionAPI } from "../../../test-utils.ts";
import { __resetState, default as registerTodo, TodoParamsSchema } from "../index.ts";

const TEST_XTODO_DIR = mkdtempSync(join(tmpdir(), "pi-xtodo-test-"));
process.env.PI_XTODO_DIR = TEST_XTODO_DIR;
after(() => {
  rmSync(TEST_XTODO_DIR, { recursive: true, force: true });
});

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

function ok(r: any, msg?: string) {
  assert.ok(!r.isError, `${msg ?? "unexpected error"}: ${r.content?.[0]?.text ?? "no text"}`);
}

function fail(r: any, msg?: string) {
  assert.ok(
    r.isError,
    `${msg ?? "expected error but got success"}: ${r.content?.[0]?.text ?? "no text"}`,
  );
}

describe("pi-xtodo", () => {
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

  it("registers todo tool and /todos command", () => {
    assert.strictEqual(pi.tools.length, 1);
    assert.strictEqual(pi.tools[0].name, "todo");
    assert.ok(pi.commands.todos);
  });

  it("schema uses String enum (not anyOf/const Literals)", () => {
    const status = (TodoParamsSchema as any).properties?.status;
    assert.ok(status, "status property missing");
    const raw = JSON.stringify(status);
    assert.ok(!raw.includes('"const"'), `status uses const literals: ${raw.slice(0, 200)}`);
  });

  it("create, update, delete, list flow", async () => {
    const t = pi.tools[0];

    // create
    const c1 = await t.execute(
      "1",
      { action: "create", subject: "Write testing suite" },
      null,
      null,
      mockCtx,
    );
    ok(c1, "create");
    assert.ok(c1.content[0].text.includes("Created #1: Write testing suite (pending)"));
    assert.strictEqual(c1.details.tasks.length, 1);
    assert.strictEqual(c1.details.tasks[0].id, 1);

    // update status + activeForm
    const u1 = await t.execute(
      "3",
      { action: "update", id: 1, status: "in_progress", activeForm: "writing" },
      null,
      null,
      mockCtx,
    );
    ok(u1, "update to in_progress");
    assert.ok(u1.content[0].text.includes("Updated #1 (pending → in_progress)"));

    // update status to completed
    const u2 = await t.execute(
      "4",
      { action: "update", id: 1, status: "completed" },
      null,
      null,
      mockCtx,
    );
    ok(u2, "update to completed");
    assert.ok(u2.content[0].text.includes("Updated #1 (in_progress → completed)"));

    // illegal transition: completed → in_progress
    const u3 = await t.execute(
      "2",
      { action: "update", id: 1, status: "in_progress" },
      null,
      null,
      mockCtx,
    );
    fail(u3, "illegal transition");
    assert.ok(u3.content[0].text.includes("illegal transition"));

    // list
    const l1 = await t.execute("5", { action: "list" }, null, null, mockCtx);
    ok(l1, "list");
    assert.ok(l1.content[0].text.includes("[completed] #1 Write testing suite"));

    // delete
    const d1 = await t.execute("6", { action: "delete", id: 1 }, null, null, mockCtx);
    ok(d1, "delete");
    assert.ok(d1.content[0].text.includes("Deleted #1"));

    // empty list
    const l2 = await t.execute("7", { action: "list" }, null, null, mockCtx);
    ok(l2, "empty list");
    assert.strictEqual(l2.content[0].text, "No tasks");
  });

  it("blockedBy cycle detection", async () => {
    const t = pi.tools[0];
    await t.execute("1", { action: "create", subject: "A" }, null, null, mockCtx);
    await t.execute("2", { action: "create", subject: "B" }, null, null, mockCtx);

    // B depends on A
    const ok1 = await t.execute(
      "3",
      { action: "update", id: 2, addBlockedBy: [1] },
      null,
      null,
      mockCtx,
    );
    ok(ok1, "B→A link");

    // A depends on B → cycle
    const bad = await t.execute(
      "4",
      { action: "update", id: 1, addBlockedBy: [2] },
      null,
      null,
      mockCtx,
    );
    fail(bad, "self-cycle A→B→A");
    assert.ok(bad.content[0].text.includes("would create a cycle"));
  });

  it("replay from branch restores state", async () => {
    const t = pi.tools[0];
    const c1 = await t.execute("1", { action: "create", subject: "T1" }, null, null, mockCtx);
    ok(c1, "create T1");
    const c2 = await t.execute("2", { action: "create", subject: "T2" }, null, null, mockCtx);
    ok(c2, "create T2");
    sessionManager.branch = [
      { type: "message", message: { role: "toolResult", toolName: "todo", details: c2.details } },
    ];
    await pi.emit("session_start", {}, mockCtx);
    const l1 = await t.execute("3", { action: "list" }, null, null, mockCtx);
    ok(l1, "list after replay");
    assert.ok(l1.content[0].text.includes("#1 T1"), "T1 restored");
    assert.ok(l1.content[0].text.includes("#2 T2"), "T2 restored");
  });

  it("persists to disk and restores", async () => {
    sessionManager.sessionId = "persist-test";
    const t = pi.tools[0];
    const c1 = await t.execute(
      "1",
      { action: "create", subject: "Persisted" },
      null,
      null,
      mockCtx,
    );
    ok(c1, "create persisted");
    sessionManager.branch = [];
    await pi.emit("session_start", {}, mockCtx);
    const l1 = await t.execute("2", { action: "list" }, null, null, mockCtx);
    ok(l1, "list after restore");
    assert.ok(l1.content[0].text.includes("#1 Persisted"));
  });

  it("coerces string ids", async () => {
    const t = pi.tools[0];
    await t.execute("1", { action: "create", subject: "Coerce" }, null, null, mockCtx);
    const r = await t.execute(
      "2",
      { action: "update", id: "1" as any, status: "in_progress" },
      null,
      null,
      mockCtx,
    );
    ok(r, "coerced string id");
    assert.ok(r.content[0].text.includes("Updated #1"));
  });

  it("rejects empty subject and mutations on deleted", async () => {
    const t = pi.tools[0];
    await t.execute("1", { action: "create", subject: "Keep" }, null, null, mockCtx);

    // empty subject on update
    const r1 = await t.execute(
      "2",
      { action: "update", id: 1, subject: "   " },
      null,
      null,
      mockCtx,
    );
    fail(r1, "empty subject");
    assert.ok(r1.content[0].text.includes("subject cannot be empty"));

    // delete
    const d1 = await t.execute("3", { action: "delete", id: 1 }, null, null, mockCtx);
    ok(d1, "delete");

    // mutation on deleted
    const r2 = await t.execute(
      "4",
      { action: "update", id: 1, subject: "ghost" },
      null,
      null,
      mockCtx,
    );
    fail(r2, "mutation on deleted");
    assert.ok(r2.content[0].text.includes("is deleted"));

    // re-delete
    const d2 = await t.execute("5", { action: "delete", id: 1 }, null, null, mockCtx);
    fail(d2, "re-delete");
    assert.ok(d2.content[0].text.includes("is already deleted"));
  });

  it("null description/activeForm/owner clears field", async () => {
    const t = pi.tools[0];
    const c1 = await t.execute(
      "1",
      {
        action: "create",
        subject: "Extras",
        description: "desc",
        activeForm: "work",
        owner: "agent",
      },
      null,
      null,
      mockCtx,
    );
    ok(c1, "create extras");

    const u1 = await t.execute(
      "2",
      {
        action: "update",
        id: 1,
        description: null as any,
        activeForm: null as any,
        owner: null as any,
      },
      null,
      null,
      mockCtx,
    );
    ok(u1, "null clearing");

    const g1 = await t.execute("3", { action: "get", id: 1 }, null, null, mockCtx);
    ok(g1, "get after null");
    assert.ok(!g1.content[0].text.includes("description:"), "description cleared");
    assert.ok(!g1.content[0].text.includes("activeForm:"), "activeForm cleared");
    assert.ok(!g1.content[0].text.includes("owner:"), "owner cleared");
  });

  it("deep blockedBy chains without false cycles", async () => {
    const t = pi.tools[0];
    for (let i = 1; i <= 8; i++) {
      const c = await t.execute(
        String(i),
        { action: "create", subject: `T${i}` },
        null,
        null,
        mockCtx,
      );
      ok(c, `create T${i}`);
    }
    for (let i = 2; i <= 8; i++) {
      const r = await t.execute(
        `u${i}`,
        { action: "update", id: i, addBlockedBy: [i - 1] },
        null,
        null,
        mockCtx,
      );
      ok(r, `link T${i}→T${i - 1}`);
    }
    // close the ring: T1→T8
    const cycle = await t.execute(
      "cycle",
      { action: "update", id: 1, addBlockedBy: [8] },
      null,
      null,
      mockCtx,
    );
    fail(cycle, "deep cycle");
    assert.ok(cycle.content[0].text.includes("would create a cycle"));
  });

  it("delete scrubs dependents blockedBy", async () => {
    const t = pi.tools[0];
    await t.execute("1", { action: "create", subject: "B1" }, null, null, mockCtx);
    await t.execute("2", { action: "create", subject: "Dep", blockedBy: [1] }, null, null, mockCtx);

    const g1 = await t.execute("g1", { action: "get", id: 2 }, null, null, mockCtx);
    assert.ok(g1.content[0].text.includes("blockedBy"), "dep has blocker before delete");

    await t.execute("3", { action: "delete", id: 1 }, null, null, mockCtx);
    const g2 = await t.execute("4", { action: "get", id: 2 }, null, null, mockCtx);
    ok(g2, "get dep after delete");
    assert.ok(!g2.content[0].text.includes("blockedBy"), "blocker scrubbed");
  });

  it("status-only update is valid", async () => {
    const t = pi.tools[0];
    await t.execute("1", { action: "create", subject: "S" }, null, null, mockCtx);
    const r = await t.execute(
      "2",
      { action: "update", id: 1, status: "in_progress" },
      null,
      null,
      mockCtx,
    );
    ok(r, "status-only update");
    assert.ok(r.content[0].text.includes("pending → in_progress"));
  });

  it("id-only update errors with field list", async () => {
    const t = pi.tools[0];
    await t.execute("1", { action: "create", subject: "N" }, null, null, mockCtx);
    const r = await t.execute("2", { action: "update", id: 1 }, null, null, mockCtx);
    fail(r, "id-only update");
    assert.ok(r.content[0].text.includes("mutable field"));
  });

  it("compact preserves in-memory state", async () => {
    const t = pi.tools[0];
    sessionManager.sessionId = "compact-session";
    await t.execute("1", { action: "create", subject: "Live" }, null, null, mockCtx);
    await pi.emit("session_start", {}, mockCtx);
    const r = await t.execute(
      "2",
      { action: "update", id: 1, status: "in_progress" },
      null,
      null,
      mockCtx,
    );
    ok(r, "update before compact");
    sessionManager.branch = [];
    await pi.emit("session_compact", {}, mockCtx);
    const list = await t.execute("3", { action: "list" }, null, null, mockCtx);
    ok(list, "list after compact");
    assert.ok(list.content[0].text.includes("[in_progress] #1 Live"));
  });

  it("rejects non-integer ids", async () => {
    const t = pi.tools[0];
    await t.execute("1", { action: "create", subject: "T" }, null, null, mockCtx);
    for (const bad of [1.5, "2.7", "1e2", 0, -1, "0", "abc"]) {
      const r = await t.execute(
        `b-${bad}`,
        { action: "update", id: bad as any, status: "in_progress" },
        null,
        null,
        mockCtx,
      );
      fail(r, `id=${JSON.stringify(bad)}`);
    }
  });

  // ------------- additional coverage -------------

  it("clear removes all tasks", async () => {
    const t = pi.tools[0];
    await t.execute("1", { action: "create", subject: "A" }, null, null, mockCtx);
    await t.execute("2", { action: "create", subject: "B" }, null, null, mockCtx);
    const r = await t.execute("3", { action: "clear" }, null, null, mockCtx);
    ok(r, "clear");
    assert.ok(r.content[0].text.includes("Cleared 2 tasks"));
    const list = await t.execute("4", { action: "list" }, null, null, mockCtx);
    assert.strictEqual(list.content[0].text, "No tasks");
  });

  it("get returns error for missing or missing-id", async () => {
    const t = pi.tools[0];
    const r1 = await t.execute("1", { action: "get", id: 999 }, null, null, mockCtx);
    fail(r1, "missing id");
    assert.ok(r1.content[0].text.includes("not found"));

    const r2 = await t.execute("2", { action: "get" }, null, null, mockCtx);
    fail(r2, "no id param");
    assert.ok(r2.content[0].text.includes("id required"));
  });

  it("rejects self-block and block on non-existent or deleted task", async () => {
    const t = pi.tools[0];
    await t.execute("1", { action: "create", subject: "Main" }, null, null, mockCtx);
    await t.execute("2", { action: "create", subject: "DelMe" }, null, null, mockCtx);

    // self-block
    const r1 = await t.execute(
      "3",
      { action: "update", id: 1, addBlockedBy: [1] },
      null,
      null,
      mockCtx,
    );
    fail(r1, "self-block");
    assert.ok(r1.content[0].text.includes("cannot block #1 on itself"));

    // non-existent
    const r2 = await t.execute(
      "4",
      { action: "update", id: 1, addBlockedBy: [999] },
      null,
      null,
      mockCtx,
    );
    fail(r2, "block on nonexistent");
    assert.ok(r2.content[0].text.includes("not found"));

    // deleted
    await t.execute("5", { action: "delete", id: 2 }, null, null, mockCtx);
    const r3 = await t.execute(
      "6",
      { action: "update", id: 1, addBlockedBy: [2] },
      null,
      null,
      mockCtx,
    );
    fail(r3, "block on deleted");
    assert.ok(r3.content[0].text.includes("is deleted"));
  });

  it("empty add/removeBlockedBy arrays are no-ops", async () => {
    const t = pi.tools[0];
    await t.execute("1", { action: "create", subject: "Base" }, null, null, mockCtx);

    const r1 = await t.execute(
      "2",
      { action: "update", id: 1, addBlockedBy: [] },
      null,
      null,
      mockCtx,
    );
    ok(r1, "empty addBlockedBy");

    const r2 = await t.execute(
      "3",
      { action: "update", id: 1, removeBlockedBy: [] },
      null,
      null,
      mockCtx,
    );
    ok(r2, "empty removeBlockedBy");

    // should still succeed — no state corruption
    const g = await t.execute("4", { action: "get", id: 1 }, null, null, mockCtx);
    ok(g, "get after empty arrays");
  });

  it("create and update with metadata", async () => {
    const t = pi.tools[0];
    const c1 = await t.execute(
      "1",
      { action: "create", subject: "Meta", metadata: { url: "https://ex.com", count: 3 } },
      null,
      null,
      mockCtx,
    );
    ok(c1, "create with metadata");
    const g1 = await t.execute("2", { action: "get", id: 1 }, null, null, mockCtx);
    // get doesn't print metadata in its output, so check details
    const g1Details = g1.details.tasks[0];
    assert.deepStrictEqual(g1Details.metadata, { url: "https://ex.com", count: 3 });

    // update: set null to remove a key, add a new key
    const u1 = await t.execute(
      "3",
      { action: "update", id: 1, metadata: { url: null, priority: "high" } },
      null,
      null,
      mockCtx,
    );
    ok(u1, "update metadata");
    const g2 = await t.execute("4", { action: "get", id: 1 }, null, null, mockCtx);
    assert.deepStrictEqual(g2.details.tasks[0].metadata, { count: 3, priority: "high" });

    // update: null out last key → metadata becomes undefined
    const u2 = await t.execute(
      "5",
      { action: "update", id: 1, metadata: { count: null, priority: null } },
      null,
      null,
      mockCtx,
    );
    ok(u2, "null all metadata");
    const g3 = await t.execute("6", { action: "get", id: 1 }, null, null, mockCtx);
    assert.strictEqual(g3.details.tasks[0].metadata, undefined);
  });

  it("list with includeDeleted shows deleted tasks", async () => {
    const t = pi.tools[0];
    await t.execute("1", { action: "create", subject: "Keep" }, null, null, mockCtx);
    await t.execute("2", { action: "create", subject: "Hide" }, null, null, mockCtx);
    await t.execute("3", { action: "delete", id: 2 }, null, null, mockCtx);

    const l1 = await t.execute("4", { action: "list" }, null, null, mockCtx);
    ok(l1, "list without deleted");
    assert.ok(!l1.content[0].text.includes("Hide"), "hidden from default list");

    const l2 = await t.execute("5", { action: "list", includeDeleted: true }, null, null, mockCtx);
    ok(l2, "list with deleted");
    assert.ok(l2.content[0].text.includes("Hide"), "visible in includeDeleted list");
  });

  it("get shows full output format", async () => {
    const t = pi.tools[0];
    await t.execute(
      "1",
      {
        action: "create",
        subject: "Detailed",
        description: "some desc",
        activeForm: "working",
        owner: "bot",
        blockedBy: [],
      },
      null,
      null,
      mockCtx,
    );

    const g = await t.execute("2", { action: "get", id: 1 }, null, null, mockCtx);
    ok(g, "get detailed");
    const text = g.content[0].text;
    assert.ok(text.includes("#1"), text);
    assert.ok(text.includes("[pending]"), text);
    assert.ok(text.includes("Detailed"), text);
    assert.ok(text.includes("description: some desc"), text);
    assert.ok(text.includes("activeForm: working"), text);
    assert.ok(text.includes("owner: bot"), text);
    // blockedBy should NOT appear since we passed []
    assert.ok(!text.includes("blockedBy:"), "empty blockedBy not printed");
    // blocks should not appear since nothing blocks it
    assert.ok(!text.includes("blocks:"), "blocks not printed");
  });

  it("removeBlockedBy for a non-existent blocker is a no-op", async () => {
    const t = pi.tools[0];
    await t.execute("1", { action: "create", subject: "Main" }, null, null, mockCtx);
    const r = await t.execute(
      "2",
      { action: "update", id: 1, removeBlockedBy: [999] },
      null,
      null,
      mockCtx,
    );
    ok(r, "remove non-existent blocker");
    const g = await t.execute("3", { action: "get", id: 1 }, null, null, mockCtx);
    ok(g, "get after remove non-existent");
    assert.ok(!g.content[0].text.includes("blockedBy"));
  });

  it("create with empty blockedBy works", async () => {
    const t = pi.tools[0];
    const r = await t.execute(
      "1",
      { action: "create", subject: "EmptyBlock", blockedBy: [] },
      null,
      null,
      mockCtx,
    );
    ok(r, "create with empty blockedBy");
    const g = await t.execute("2", { action: "get", id: 1 }, null, null, mockCtx);
    ok(g, "get empty block");
    assert.ok(!g.content[0].text.includes("blockedBy"), "no blockedBy rendered");
  });

  it("removes duplicate ids in blockedBy", async () => {
    const t = pi.tools[0];
    await t.execute("1", { action: "create", subject: "Target" }, null, null, mockCtx);
    await t.execute("2", { action: "create", subject: "Dep" }, null, null, mockCtx);
    const r = await t.execute(
      "3",
      { action: "update", id: 2, addBlockedBy: [1, 1, 1] },
      null,
      null,
      mockCtx,
    );
    ok(r, "deduplicate blocker list");
    assert.ok(!r.content[0].text.includes("Error"), "no error on dedup");
    const g = await t.execute("4", { action: "get", id: 2 }, null, null, mockCtx);
    // should only list #1 once
    const match = g.content[0].text.match(/#1/g);
    assert.strictEqual(match?.length, 1, "exactly one #1 reference");
  });
});
