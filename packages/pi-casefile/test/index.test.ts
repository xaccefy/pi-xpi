import { afterEach, beforeEach, describe, expect, mock, test } from "bun:test";
import { readFileSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { setCasefilePath } from "../src/ledger.ts";

mock.module("@earendil-works/pi-ai", () => ({
  StringEnum: (values: readonly string[]) => ({ enum: values }),
}));

mock.module("typebox", () => ({
  Type: {
    Array: (item: unknown, options?: Record<string, unknown>) => ({ item, ...options }),
    Number: (options?: Record<string, unknown>) => ({ type: "number", ...options }),
    Object: (properties: Record<string, unknown>, options?: Record<string, unknown>) => ({
      type: "object",
      properties,
      ...options,
    }),
    Optional: (schema: unknown) => schema,
    String: (options?: Record<string, unknown>) => ({ type: "string", ...options }),
  },
}));

mock.module("@earendil-works/pi-tui", () => ({
  Text: class Text {
    constructor(
      public text: string,
      public x: number,
      public y: number,
    ) {}
  },
  matchesKey: (data: string, key: string) => data === key,
  truncateToWidth: (value: string, width: number) => value.slice(0, width),
}));

mock.module("../src/poc-runner.ts", () => ({
  runPoc: () => ({
    path: "/mock/poc.sh",
    exitCode: 0,
    output: "ok",
    ranAt: "2024-01-01T00:00:00Z",
    sandbox: true,
  }),
}));

type FakePi = {
  tools: Map<string, any>;
  commands: Map<string, any>;
  events: Map<string, any[]>;
  registerTool(tool: any): void;
  registerCommand(name: string, command: any): void;
  on(event: string, handler: any): void;
};

let tempDir: string;
let casefileExtension: (pi: any) => void;

function createFakePi(): FakePi {
  return {
    tools: new Map(),
    commands: new Map(),
    events: new Map(),
    registerTool(tool) {
      this.tools.set(tool.name, tool);
    },
    registerCommand(name, command) {
      this.commands.set(name, command);
    },
    on(event, handler) {
      this.events.set(event, [...(this.events.get(event) ?? []), handler]);
    },
  };
}

async function executeTool(pi: FakePi, name: string, params: Record<string, unknown>) {
  const tool = pi.tools.get(name);
  if (!tool) throw new Error(`Tool not registered: ${name}`);
  return tool.execute("test-call", params, new AbortController().signal, () => undefined, {});
}

beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), "casefile-index-test-"));
  setCasefilePath(join(tempDir, "casefile.db"));
  casefileExtension = (await import("../src/index.ts")).default;
});

afterEach(async () => {
  setCasefilePath(undefined);
  await rm(tempDir, { recursive: true, force: true });
});

describe("casefile extension", () => {
  test("registers the expected tools, command, and lifecycle events", () => {
    const pi = createFakePi();
    casefileExtension(pi as any);

    expect([...pi.tools.keys()].sort()).toEqual([
      "CaseAdd",
      "CaseGet",
      "CaseLink",
      "CaseList",
      "CaseReport",
      "CaseSearch",
      "CaseUnlink",
      "CaseUpdate",
      "PromoteFinding",
    ]);
    expect([...pi.commands.keys()]).toEqual(["casefile"]);
    expect(pi.events.has("session_start")).toBe(true);
    expect(pi.events.has("before_agent_start")).toBe(true);
    expect(pi.events.has("tool_result")).toBe(true);

    const addProperties = pi.tools.get("CaseAdd").parameters.properties;
    const updateProperties = pi.tools.get("CaseUpdate").parameters.properties;
    expect(addProperties.linked_case_ids).toBeUndefined();
    expect(updateProperties.linked_case_ids).toBeUndefined();
    const field = pi.tools.get("CaseSearch").parameters.properties.field;
    const values = field.anyOf.map((f: any) => f.const);
    expect(values).toContain("poc");
  });

  test("executes the add, get, update, list, search, and report tools", async () => {
    const pi = createFakePi();
    casefileExtension(pi as any);

    const added = await executeTool(pi, "CaseAdd", {
      title: "Sensitive file disclosure",
      status: "investigating",
      confidence: "medium",
      severity: "medium",
      priority: "P1",
      target: "app.example.test",
      endpoint: "/download",
      bugClass: "IDOR",
      summary: "Downloads are authorized by object ID only",
      evidence: "download?id=42 returns another user's file",
      nextStep: "Confirm access as a second account",
      tags: ["idor"],
    });
    const record = added.details.record;
    expect(added.details.created).toBe(true);

    const fetched = await executeTool(pi, "CaseGet", { id: record.id });
    expect(fetched.content[0].text).toContain("Sensitive file disclosure");
    expect(fetched.details.record.bugClass).toBe("IDOR");
    expect(fetched.details.record.summary).toBe("Downloads are authorized by object ID only");

    const updated = await executeTool(pi, "CaseUpdate", {
      id: record.id,
      confidence: "high",
      severity: "medium",
      poc: "Fetch /download?id=42 with a different session",
      impact: "Unauthorized access to other users' files",
      evidence: "download?id=42 returns another user's file",
    });
    expect(updated.details.changed).toBe(true);

    const promoted = await executeTool(pi, "PromoteFinding", {
      id: record.id,
      poc_path: "/mock/poc.sh",
    });
    expect(promoted.details.record.status).toBe("confirmed");
    expect(promoted.details.record.pocVerified?.exitCode).toBe(0);
    expect(promoted.details.record.evidence).toContain("PoC Execution Capture");
    expect(promoted.details.record.evidence).toContain("Execution Output\n```\nok\n```");

    const listed = await executeTool(pi, "CaseList", { status: "confirmed" });
    expect(listed.details.total).toBe(1);
    expect(listed.content[0].text).toContain(record.id);

    const searched = await executeTool(pi, "CaseSearch", {
      query: "different session",
      field: "poc",
      priority: "P1",
    });
    expect(searched.details.total).toBe(1);
    expect(searched.details.cases[0].id).toBe(record.id);

    const report = await executeTool(pi, "CaseReport", { id: record.id });
    expect(report.details.path).toMatch(/sensitive-file-disclosure-case_[a-f0-9]{10}\.md$/);

    const reportText = readFileSync(report.details.path, "utf8");
    expect(reportText).toContain("PoC Verification Log");
    expect(reportText).toContain("Output\n```\nok\n```");
  });

  test("returns the existing case when CaseAdd repeats the same title and scope", async () => {
    const pi = createFakePi();
    casefileExtension(pi as any);

    const first = await executeTool(pi, "CaseAdd", {
      title: "Provider metadata injection",
      target: "packages/ai",
      bugClass: "validation bypass",
      evidence: "Initial audit note",
    });
    const duplicate = await executeTool(pi, "CaseAdd", {
      title: " provider metadata   injection ",
      target: "packages/ai",
      bugClass: "Validation Bypass",
      evidence: "Repeated audit note",
    });

    expect(duplicate.details.created).toBe(false);
    expect(duplicate.details.record.id).toBe(first.details.record.id);
    expect(duplicate.content[0].text).toContain("Case already exists");

    const listed = await executeTool(pi, "CaseList", {});
    expect(listed.details.total).toBe(1);
  });

  test("links and unlinks cases through registered tools", async () => {
    const pi = createFakePi();
    casefileExtension(pi as any);

    const first = await executeTool(pi, "CaseAdd", {
      title: "Open redirect",
      evidence: "next parameter accepts arbitrary URL",
    });
    const second = await executeTool(pi, "CaseAdd", {
      title: "OAuth callback abuse",
      evidence: "callback can consume redirected authorization code",
    });

    const linked = await executeTool(pi, "CaseLink", {
      source_id: first.details.record.id,
      target_id: second.details.record.id,
    });
    expect(linked.details.source.linkedCaseIds).toEqual([second.details.record.id]);
    expect(linked.details.target.linkedCaseIds).toEqual([first.details.record.id]);

    const duplicateLink = await executeTool(pi, "CaseLink", {
      source_id: first.details.record.id,
      target_id: second.details.record.id,
    });
    expect(duplicateLink.details.changed).toBe(false);
    expect(duplicateLink.content[0].text).toContain("Link unchanged");

    const unlinked = await executeTool(pi, "CaseUnlink", {
      source_id: first.details.record.id,
      target_id: second.details.record.id,
    });
    expect(unlinked.details.source.linkedCaseIds).toEqual([]);
    expect(unlinked.details.target.linkedCaseIds).toEqual([]);

    const duplicateUnlink = await executeTool(pi, "CaseUnlink", {
      source_id: first.details.record.id,
      target_id: second.details.record.id,
    });
    expect(duplicateUnlink.details.changed).toBe(false);
    expect(duplicateUnlink.content[0].text).toContain("Unlink unchanged");
  });

  test("always injects cyber workflow even with an empty ledger", async () => {
    const pi = createFakePi();
    casefileExtension(pi as any);

    const handler = pi.events.get("before_agent_start")?.[0];
    expect(handler).toBeFunction();
    const result = await handler();

    expect(result.message.customType).toBe("casefile_summary");
    expect(result.message.display).toBe(false);
    expect(result.message.content).toContain("# Cyber Workflow");
    expect(result.message.content).toContain("Evidence-First Doctrine");
    expect(result.message.content).not.toContain("<casefile_context>");
  });

  test("injects only active cases into before_agent_start context", async () => {
    const pi = createFakePi();
    casefileExtension(pi as any);

    await executeTool(pi, "CaseAdd", {
      title: "Active <payload> lead",
      status: "investigating",
      summary: "This should not be injected",
      evidence: "Observed suspicious response",
      confidence: "low",
      nextStep: "Test <payload> safely",
    });
    const killed = await executeTool(pi, "CaseAdd", {
      title: "Killed duplicate",
      status: "investigating",
      evidence: "Duplicate",
      confidence: "low",
    });
    await executeTool(pi, "CaseUpdate", {
      id: killed.details.record.id,
      status: "killed",
      assumptions: ["Duplicate lead with no new evidence"],
    });
    const reported = await executeTool(pi, "CaseAdd", {
      title: "Already reported",
      status: "investigating",
      evidence: "Resolved finding",
      confidence: "high",
      poc: "Reproduced before patch",
      impact: "Was exploitable",
      severity: "high",
      remediation: "Patch shipped",
    });
    await executeTool(pi, "PromoteFinding", {
      id: reported.details.record.id,
      poc_path: "/mock/poc.sh",
    });
    await executeTool(pi, "CaseReport", { id: reported.details.record.id });
    await executeTool(pi, "CaseUpdate", {
      id: reported.details.record.id,
      status: "reported",
      remediation: "Patch shipped",
    });

    const handler = pi.events.get("before_agent_start")?.[0];
    expect(handler).toBeFunction();

    const result = await handler();
    expect(result.message.customType).toBe("casefile_summary");
    expect(result.message.display).toBe(false);
    expect(result.message.content).toContain("Active security cases: 1 total");
    expect(result.message.content).toContain("Active ‹payload› lead");
    expect(result.message.content).toContain("Test ‹payload› safely");
    expect(result.message.content).not.toContain("This should not be injected");
    expect(result.message.content).not.toContain("Killed duplicate");
    expect(result.message.content).not.toContain("Already reported");
    // Workflow still rides along with the case list.
    expect(result.message.content).toContain("# Cyber Workflow");
  });

  test("includes hypothesis and blocked cases in prompt context", async () => {
    const pi = createFakePi();
    casefileExtension(pi as any);

    await executeTool(pi, "CaseAdd", {
      title: "Hypothesis lead",
      status: "hypothesis",
    });
    const blocked = await executeTool(pi, "CaseAdd", {
      title: "Blocked lead",
      status: "investigating",
      evidence: "Need env access",
      confidence: "low",
    });
    await executeTool(pi, "CaseUpdate", {
      id: blocked.details.record.id,
      status: "blocked",
      blockers: ["Needs environment access"],
    });

    const handler = pi.events.get("before_agent_start")?.[0];
    const result = await handler();

    expect(result.message.content).toContain("Hypothesis lead");
    expect(result.message.content).toContain("Blocked lead");
  });

  test("supports the non-ui dashboard command and status updates", async () => {
    const pi = createFakePi();
    casefileExtension(pi as any);

    const storedXss = await executeTool(pi, "CaseAdd", {
      title: "Stored XSS",
      status: "investigating",
      evidence: "Payload renders in notes",
      confidence: "high",
      poc: "Render a note containing <img src=x onerror=alert(1)> and observe execution",
      impact: "Script execution in victim browser",
      severity: "high",
    });
    await executeTool(pi, "PromoteFinding", {
      id: storedXss.details.record.id,
      poc_path: "/mock/poc.sh",
    });

    const notifications: string[] = [];
    const statuses: Record<string, string> = {};
    const ctx = {
      hasUI: false,
      ui: {
        notify(message: string) {
          notifications.push(message);
        },
        setStatus(key: string, value: string) {
          statuses[key] = value;
        },
      },
    };

    await pi.commands.get("casefile").handler("", ctx);
    expect(notifications[0]).toContain("Casefile: 1 total");
    expect(notifications[0]).toContain("confirmed:1");

    const handler = pi.events.get("tool_result")?.[0];
    expect(handler).toBeFunction();
    await handler({ toolName: "CaseAdd" }, ctx);
    expect(statuses.casefile).toBe("1 cases");
  });
});
