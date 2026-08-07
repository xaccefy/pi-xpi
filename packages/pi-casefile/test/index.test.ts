import { afterEach, beforeEach, describe, expect, mock, test } from "bun:test";
import { readFileSync, writeFileSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { setCasefilePath } from "../src/ledger.ts";
import { setScratchpadRoot } from "../src/scratchpad.ts";
import { STATIC_CYBER_WORKFLOW, STATIC_CYBER_WORKFLOW_LITE } from "../src/workflow.ts";

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

// NOTE: Do NOT mock poc-runner.ts here — mock.module() is process-global in Bun
// and would replace the real runPoc for every test file in the same run.
// Instead we create a real temp PoC script in beforeEach and pass local:true.

type FakePi = {
  tools: Map<string, any>;
  commands: Map<string, any>;
  events: Map<string, any[]>;
  registerTool(tool: any): void;
  registerCommand(name: string, command: any): void;
  on(event: string, handler: any): void;
};

let tempDir: string;
let pocScriptPath: string;
let controlScriptPath: string;
let observationArtifactPath: string;
let disconfirmationScriptPath: string;
let casefileExtension: (pi: any) => void;

// CaseAdd now requires disproveIf (falsification conditions); the tool-level
// helper injects a default so the fixture-driven tests stay focused on the
// behavior they exercise. Promotion additionally requires an observation
// evidence item (evidence-chain closure), so the helper records one.
async function addCase(pi: FakePi, fields: Record<string, unknown>) {
  const result = await executeTool(pi, "CaseAdd", {
    disproveIf: ["test: finding is actually intended behavior"],
    ...fields,
  });
  if (result.details?.record?.id) {
    await executeTool(pi, "EvidenceAdd", {
      case_id: result.details.record.id,
      role: "observation",
      summary: "test fixture: initial observed signal",
      artifact_path: observationArtifactPath,
    }).catch(() => undefined);
  }
  return result;
}

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
  setScratchpadRoot(tempDir);
  pocScriptPath = join(tempDir, "shared.sh");
  // Same-file contract: the control must be the SAME script as the PoC
  // (sha256-equal; the only permitted difference is PI_POC_MODE). The shared
  // fixture branches: poc mode prints the marker, control mode prints the
  // liveness marker only, disconfirmation is a separate exit-1 script.
  writeFileSync(
    pocScriptPath,
    "#!/bin/sh\nif [ \"$PI_POC_MODE\" = \"control\" ]; then\n  echo 'CONTROL_REACHED_1'\n  exit 0\nfi\nprintf 'ok'",
    "utf8",
  );
  controlScriptPath = pocScriptPath;
  observationArtifactPath = join(tempDir, "observation.txt");
  writeFileSync(observationArtifactPath, "observed signal (fixture)", "utf8");
  disconfirmationScriptPath = join(tempDir, "disconf.sh");
  writeFileSync(disconfirmationScriptPath, "#!/bin/sh\nexit 1", "utf8");
  process.env.PI_POC_ROOT = tempDir;
  // Local (host) execution is operator-gated; the test harness FORCE_LOCAL
  // so promote tests run hermetically without Docker even when Docker is
  // installed — production still prefers the host-network sandbox.
  process.env.PI_POC_ALLOW_LOCAL = "1";
  process.env.PI_POC_FORCE_LOCAL = "1";
  // Hermeticity: the before_agent_start handler skips injection when
  // PI_SUBAGENT_CHILD=1 (the harness sets it when running inside pi-subagents);
  // without this, the whole XP-mode suite fails under subagent execution.
  delete process.env.PI_SUBAGENT_CHILD;
  casefileExtension = (await import("../src/index.ts")).default;
});

afterEach(async () => {
  setCasefilePath(undefined);
  setScratchpadRoot(undefined);
  delete process.env.PI_POC_ROOT;
  delete process.env.PI_POC_ALLOW_LOCAL;
  delete process.env.PI_POC_FORCE_LOCAL;
  await rm(tempDir, { recursive: true, force: true });
});

describe("casefile extension", () => {
  test("registers the expected tools, command, and lifecycle events", () => {
    const pi = createFakePi();
    casefileExtension(pi as any);

    expect([...pi.tools.keys()].sort()).toEqual([
      "CaseAdd",
      "CaseContext",
      "CaseGet",
      "CaseLink",
      "CaseList",
      "CaseSearch",
      "CaseUnlink",
      "CaseUpdate",
      "ChainSuggest",
      "CoverageAdd",
      "CoverageReport",
      "EvidenceAdd",
      "PipelineSubmit",
      "PromoteFinding",
      "ScratchpadCheckpoint",
      "ScratchpadClear",
      "ScratchpadInit",
      "ScratchpadPhaseDone",
      "ScratchpadRead",
      "ScratchpadResume",
      "ScratchpadWrite",
    ]);
    expect([...pi.commands.keys()].sort()).toEqual(["casefile", "xp"]);
    expect(pi.events.has("session_start")).toBe(true);
    expect(pi.events.has("before_agent_start")).toBe(true);
    expect(pi.events.has("tool_result")).toBe(true);

    const addProperties = pi.tools.get("CaseAdd").parameters.properties;
    const updateProperties = pi.tools.get("CaseUpdate").parameters.properties;
    expect(addProperties.linked_case_ids).toBeUndefined();
    expect(updateProperties.linked_case_ids).toBeUndefined();
    const field = pi.tools.get("CaseSearch").parameters.properties.field;
    const values = field.enum as string[];
    expect(values).toContain("poc");
  });

  test("executes the add, get, update, list, search, and report tools", async () => {
    const pi = createFakePi();
    casefileExtension(pi as any);

    const added = await addCase(pi, {
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
      disconfirmation: "Attempted to access own file without session token; blocked.",
    });
    expect(updated.details.changed).toBe(true);

    const promoted = await executeTool(pi, "PromoteFinding", {
      id: record.id,
      poc_path: pocScriptPath,
      verification_marker: "ok",
      control_path: controlScriptPath,
      control_liveness_marker: "CONTROL_REACHED_1",
      disconfirmation_path: disconfirmationScriptPath,
      local: true,
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

    const report = await executeTool(pi, "CaseContext", { id: record.id });
    expect(report.details.path).toMatch(/sensitive-file-disclosure-case_[a-f0-9]{10}\.md$/);
    expect(report.details.contextPath).toMatch(/\.context\.md$/);

    // Rich content (verification logs, links, complete record) lives in the
    // context bundle; the report path is reserved for the reporter agent.
    const contextText = readFileSync(report.details.contextPath, "utf8");
    expect(contextText).toContain("PoC Verification Log");
    expect(contextText).toContain("Output\n```\nok\n```");
    expect(contextText).toContain("Complete Case Record");
    expect(contextText).toContain("Linked Cases");
  });

  test("PromoteFinding requires control_path + control_liveness_marker for EVERY promotion (sandboxed and live)", async () => {
    const pi = createFakePi();
    casefileExtension(pi as any);

    const added = await addCase(pi, {
      title: "No control path",
      status: "investigating",
      evidence: "reflected input",
      confidence: "high",
      severity: "medium",
      poc: "send payload, check reflection",
      impact: "script execution",
      target: "example-app",
      disconfirmation: "tried without payload; no reflection",
    });
    const id = added.details.record.id;

    // Missing control_path — blocked even WITHOUT local:true (the default
    // sandboxed mode used to skip the control entirely; now it is mandatory).
    const noControl = await executeTool(pi, "PromoteFinding", {
      id,
      poc_path: pocScriptPath,
      verification_marker: "ok",
      control_liveness_marker: "CONTROL_REACHED_1",
    });
    expect(noControl.isError).toBe(true);
    expect(noControl.content[0].text).toContain("control_path");
    expect(noControl.details.missingControl).toBe(true);
    expect(noControl.details.record.status).toBe("investigating");

    // Same for live findings.
    const noControlLive = await executeTool(pi, "PromoteFinding", {
      id,
      poc_path: pocScriptPath,
      verification_marker: "ok",
      local: true,
    });
    expect(noControlLive.isError).toBe(true);
    expect(noControlLive.content[0].text).toContain("control_path");
    expect(noControlLive.details.record.status).toBe("investigating");

    // Missing control_liveness_marker — blocked before any PoC run.
    const noLiveness = await executeTool(pi, "PromoteFinding", {
      id,
      poc_path: pocScriptPath,
      verification_marker: "ok",
      control_path: controlScriptPath,
    });
    expect(noLiveness.isError).toBe(true);
    expect(noLiveness.content[0].text).toContain("control_liveness_marker");
    expect(noLiveness.details.missingLivenessMarker).toBe(true);
    expect(noLiveness.details.record.status).toBe("investigating");

    // A liveness marker identical to the verification marker is rejected.
    const sameMarker = await executeTool(pi, "PromoteFinding", {
      id,
      poc_path: pocScriptPath,
      verification_marker: "ok",
      control_path: controlScriptPath,
      control_liveness_marker: "ok",
    });
    expect(sameMarker.isError).toBe(true);
    expect(sameMarker.details.livenessEqualsMarker).toBe(true);
    expect(sameMarker.details.record.status).toBe("investigating");
  });

  test("PromoteFinding requires disconfirmation_path for severity high/critical", async () => {
    const pi = createFakePi();
    casefileExtension(pi as any);

    const added = await addCase(pi, {
      title: "High severity without disconfirmation script",
      status: "investigating",
      evidence: "reflected input",
      confidence: "high",
      severity: "high",
      poc: "send payload, check reflection",
      impact: "script execution",
      target: "example-app",
      disconfirmation: "tried without payload; no reflection",
    });
    const id = added.details.record.id;

    const result = await executeTool(pi, "PromoteFinding", {
      id,
      poc_path: pocScriptPath,
      verification_marker: "ok",
      control_path: controlScriptPath,
      control_liveness_marker: "CONTROL_REACHED_1",
      local: true,
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("disconfirmation_path");
    expect(result.details.missingDisconfirmation).toBe(true);
    expect(result.details.record.status).toBe("investigating");
  });

  test("PromoteFinding blocks a PoC whose marker appears in the control-target run (cheat)", async () => {
    const pi = createFakePi();
    casefileExtension(pi as any);

    const added = await addCase(pi, {
      title: "Cheating PoC",
      status: "investigating",
      evidence: "reflected input",
      confidence: "high",
      severity: "medium",
      poc: "send payload, check reflection",
      impact: "script execution",
      target: "example-app",
      disconfirmation: "tried without payload; no reflection",
    });
    const id = added.details.record.id;

    // The control script is the SAME file as the PoC (same-file contract) but
    // its control branch echoes the marker unconditionally — the way a
    // cheating PoC prints it without the vulnerable condition. The harness
    // must block promotion even though the PoC run itself "succeeded".
    const cheatScript = join(tempDir, "cheat.sh");
    writeFileSync(
      cheatScript,
      "#!/bin/sh\nif [ \"$PI_POC_MODE\" = \"control\" ]; then\n  printf 'ok'\n  echo 'CONTROL_REACHED_1'\n  exit 0\nfi\nprintf 'ok'",
      "utf8",
    );

    const result = await executeTool(pi, "PromoteFinding", {
      id,
      poc_path: cheatScript,
      verification_marker: "ok",
      control_path: cheatScript,
      control_liveness_marker: "CONTROL_REACHED_1",
      disconfirmation_path: disconfirmationScriptPath,
      local: true,
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("CONTROL CHECK FAILED");
    expect(result.details.controlCheated).toBe(true);
    expect(result.details.record.status).toBe("investigating");
  });

  test("PromoteFinding blocks a control script that crashes before running (no completion)", async () => {
    const pi = createFakePi();
    casefileExtension(pi as any);

    const added = await addCase(pi, {
      title: "Crashing control",
      status: "investigating",
      evidence: "reflected input",
      confidence: "high",
      severity: "medium",
      poc: "send payload, check reflection",
      impact: "script execution",
      target: "example-app",
      disconfirmation: "tried without payload; no reflection",
    });
    const id = added.details.record.id;

    // A control script that kills itself never runs to completion — the gate
    // must NOT treat "no marker in crash output" as a clean control verdict.
    // Same-file contract: poc and control are the SAME script.
    const crashControl = join(tempDir, "crash-control.sh");
    writeFileSync(
      crashControl,
      '#!/bin/sh\nif [ "$PI_POC_MODE" = "control" ]; then\n  kill -9 $$\nfi\nprintf \'ok\'',
      "utf8",
    );

    const result = await executeTool(pi, "PromoteFinding", {
      id,
      poc_path: crashControl,
      verification_marker: "ok",
      control_path: crashControl,
      control_liveness_marker: "CONTROL_REACHED_1",
      disconfirmation_path: disconfirmationScriptPath,
      local: true,
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("did NOT complete");
    expect(result.details.controlCrashed).toBe(true);
    expect(result.details.record.status).toBe("investigating");
  });

  test("PromoteFinding blocks a control that completed WITHOUT the liveness marker", async () => {
    const pi = createFakePi();
    casefileExtension(pi as any);

    const added = await addCase(pi, {
      title: "Dead control",
      status: "investigating",
      evidence: "reflected input",
      confidence: "high",
      severity: "medium",
      poc: "send payload, check reflection",
      impact: "script execution",
      target: "example-app",
      disconfirmation: "tried without payload; no reflection",
    });
    const id = added.details.record.id;

    // The control exits cleanly and never prints the vuln marker — but it also
    // never reaches the control target (no liveness marker). A control pointed
    // at an unreachable host / wrong port / early exit is NOT a clean verdict.
    // Same-file contract: poc and control are the SAME script.
    const deadControl = join(tempDir, "dead-control.sh");
    writeFileSync(
      deadControl,
      '#!/bin/sh\nif [ "$PI_POC_MODE" = "control" ]; then\n  exit 0\nfi\nprintf \'ok\'',
      "utf8",
    );

    const result = await executeTool(pi, "PromoteFinding", {
      id,
      poc_path: deadControl,
      verification_marker: "ok",
      control_path: deadControl,
      control_liveness_marker: "CONTROL_REACHED_1",
      disconfirmation_path: disconfirmationScriptPath,
      local: true,
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("CONTROL CHECK FAILED");
    expect(result.content[0].text).toContain("control_liveness_marker");
    expect(result.details.controlLivenessMissing).toBe(true);
    expect(result.details.record.status).toBe("investigating");
  });

  test("CoverageReport renders unbacked cells distinctly", async () => {
    const pi = createFakePi();
    casefileExtension(pi as any);

    const added = await addCase(pi, { title: "Unbacked coverage", status: "hypothesis" });
    const id = added.details.record.id;

    // Backed cell: artifact-backed observation evidence item on the case.
    const ev = await executeTool(pi, "EvidenceAdd", {
      case_id: id,
      role: "observation",
      summary: "probe log",
      artifact_path: observationArtifactPath,
    });
    await executeTool(pi, "CoverageAdd", {
      case_id: id,
      asset: "example-app",
      class: "sql-injection",
      scope: "local",
      note: "payloads on all params; no injection",
      evidence_item_id: ev.details.item.id,
    });
    // Unbacked cell: no evidence link.
    await executeTool(pi, "CoverageAdd", {
      case_id: id,
      asset: "example-app",
      class: "ssti",
      scope: "local",
      note: "no reflection",
    });

    const report = await executeTool(pi, "CoverageReport", { case_id: id });
    const text = report.content[0].text;
    const sqliLine = text.split("\n").find((l: string) => l.includes("sql-injection"))!;
    const sstiLine = text.split("\n").find((l: string) => l.includes("ssti"))!;
    expect(sqliLine).toContain("sql-injection");
    expect(sqliLine).not.toContain("⚠ unbacked");
    expect(sstiLine).toContain("ssti");
    expect(sstiLine).toContain("⚠ unbacked");
  });

  test("PromoteFinding blocks a crashed disconfirmation script (crash is not survived disproof)", async () => {
    const pi = createFakePi();
    casefileExtension(pi as any);

    const added = await addCase(pi, {
      title: "Crashing disconfirmation",
      status: "investigating",
      evidence: "reflected input",
      confidence: "high",
      severity: "medium",
      poc: "send payload, check reflection",
      impact: "script execution",
      target: "example-app",
      disconfirmation: "tried without payload; no reflection",
    });
    const id = added.details.record.id;

    const crashDisconf = join(tempDir, "crash-disconf.sh");
    writeFileSync(crashDisconf, "#!/bin/sh\nkill -9 $$\n", "utf8");

    const result = await executeTool(pi, "PromoteFinding", {
      id,
      poc_path: pocScriptPath,
      verification_marker: "ok",
      disconfirmation_path: crashDisconf,
      control_path: controlScriptPath,
      control_liveness_marker: "CONTROL_REACHED_1",
      local: true,
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("did NOT complete");
    expect(result.details.disconfirmationCrashed).toBe(true);
    expect(result.details.record.status).toBe("investigating");
  });

  test("CoverageAdd records cells and CoverageReport renders the matrix", async () => {
    const pi = createFakePi();
    casefileExtension(pi as any);

    const added = await addCase(pi, { title: "Coverage target", status: "hypothesis" });
    const id = added.details.record.id;

    const wide = await executeTool(pi, "CoverageAdd", {
      case_id: id,
      asset: "example-app",
      class: "sql-injection",
      scope: "wide",
      note: "ffuf + manual on all params; no injection",
    });
    expect(wide.details.item.scope).toBe("wide");

    const report = await executeTool(pi, "CoverageReport", { case_id: id });
    expect(report.content[0].text).toContain("sql-injection");
    expect(report.content[0].text).toContain("example-app");
  });

  test("ChainSuggest surfaces cross-case chains", async () => {
    const pi = createFakePi();
    casefileExtension(pi as any);

    const cred = await addCase(pi, {
      title: "Leaked API key",
      status: "investigating",
      confidence: "medium",
      target: "example-app",
      evidence: "key in public repo",
    });
    await addCase(pi, {
      title: "Admin login endpoint",
      status: "investigating",
      confidence: "medium",
      target: "example-app",
      evidence: "login accepts credentials",
    });

    const suggestions = await executeTool(pi, "ChainSuggest", { case_id: cred.details.record.id });
    expect(suggestions.content[0].text).toContain("credential_endpoint");
    expect(suggestions.details.suggestions.length).toBeGreaterThan(0);
  });

  test("PromoteFinding rejects a PoC that exits 0 but lacks the verification marker", async () => {
    const pi = createFakePi();
    casefileExtension(pi as any);

    const added = await addCase(pi, {
      title: "Missing marker PoC",
      target: "example-app",
      bugClass: "xss",
      evidence: "reflected input",
    });
    const id = added.details.record.id;
    await executeTool(pi, "CaseUpdate", {
      id,
      status: "investigating",
      confidence: "high",
      severity: "medium",
      poc: "send payload, check reflection",
      impact: "script execution",
      target: "example-app",
      disconfirmation: "tried without payload; no reflection",
    });

    // PoC prints 'ok' but we require a marker that is NOT in the output.
    const result = await executeTool(pi, "PromoteFinding", {
      id,
      poc_path: pocScriptPath,
      verification_marker: "VULN_CONFIRMED_not_present",
      control_path: controlScriptPath,
      control_liveness_marker: "CONTROL_REACHED_1",
      disconfirmation_path: disconfirmationScriptPath,
      local: true,
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("verification marker");
    expect(result.details.record.status).toBe("investigating");
  });

  test("returns the existing case when CaseAdd repeats the same title and scope", async () => {
    const pi = createFakePi();
    casefileExtension(pi as any);

    const first = await addCase(pi, {
      title: "Provider metadata injection",
      target: "packages/ai",
      bugClass: "validation bypass",
      evidence: "Initial audit note",
    });
    const duplicate = await addCase(pi, {
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

    const first = await addCase(pi, {
      title: "Open redirect",
      evidence: "next parameter accepts arbitrary URL",
    });
    const second = await addCase(pi, {
      title: "OAuth callback abuse",
      evidence: "callback can consume redirected authorization code",
    });

    const linked = await executeTool(pi, "CaseLink", {
      source_id: first.details.record.id,
      target_id: second.details.record.id,
    });
    expect(linked.details.source.linkedCases.map((l: { id: string }) => l.id)).toEqual([
      second.details.record.id,
    ]);
    expect(linked.details.target.linkedCases.map((l: { id: string }) => l.id)).toEqual([
      first.details.record.id,
    ]);

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
    expect(unlinked.details.source.linkedCases.map((l: { id: string }) => l.id)).toEqual([]);
    expect(unlinked.details.target.linkedCases.map((l: { id: string }) => l.id)).toEqual([]);

    const duplicateUnlink = await executeTool(pi, "CaseUnlink", {
      source_id: first.details.record.id,
      target_id: second.details.record.id,
    });
    expect(duplicateUnlink.details.changed).toBe(false);
    expect(duplicateUnlink.content[0].text).toContain("Unlink unchanged");
  });

  test("CaseLink records a typed relationship kind and surfaces it", async () => {
    const pi = createFakePi();
    casefileExtension(pi as any);

    const first = await addCase(pi, { title: "Auth bypass root" });
    const second = await addCase(pi, { title: "Token leak symptom" });

    const linked = await executeTool(pi, "CaseLink", {
      source_id: first.details.record.id,
      target_id: second.details.record.id,
      kind: "caused-by",
    });
    expect(linked.details.changed).toBe(true);
    expect(linked.details.kind).toBe("caused-by");
    expect(linked.content[0].text).toContain("[caused-by]");
    // Inverse is written to the reverse row so the target sees "causes".
    expect(linked.details.target.linkedCases).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: first.details.record.id, kind: "causes" }),
      ]),
    );
  });

  test("XP mode is off by default: before_agent_start injects nothing", async () => {
    const previous = process.env.PI_XP_MODE;
    delete process.env.PI_XP_MODE;
    try {
      const pi = createFakePi();
      casefileExtension(pi as any);

      const handler = pi.events.get("before_agent_start")?.[0];
      expect(handler).toBeFunction();
      const result = await handler();
      expect(result).toBeUndefined();
    } finally {
      if (previous === undefined) delete process.env.PI_XP_MODE;
      else process.env.PI_XP_MODE = previous;
    }
  });

  test("XP mode lite: injects the single-agent workflow, not the full pipeline", async () => {
    const previous = process.env.PI_XP_MODE;
    process.env.PI_XP_MODE = "lite";
    try {
      const pi = createFakePi();
      casefileExtension(pi as any);

      const handler = pi.events.get("before_agent_start")?.[0];
      expect(handler).toBeFunction();
      const event = { systemPrompt: "existing prompt" };
      const result = await handler(event);

      expect(result.systemPrompt).toContain("existing prompt");
      expect(result.systemPrompt).toContain("# Cyber Workflow — LITE (Single-Agent)");
      expect(result.systemPrompt).toContain("Do NOT dispatch subagents");
      expect(result.systemPrompt).not.toContain("Evidence-First Doctrine");
    } finally {
      if (previous === undefined) delete process.env.PI_XP_MODE;
      else process.env.PI_XP_MODE = previous;
    }
  });

  test("XP mode on: injects cyber workflow even with an empty ledger", async () => {
    const previous = process.env.PI_XP_MODE;
    process.env.PI_XP_MODE = "on";
    try {
      const pi = createFakePi();
      casefileExtension(pi as any);

      const handler = pi.events.get("before_agent_start")?.[0];
      expect(handler).toBeFunction();
      const event = { systemPrompt: "existing prompt" };
      const result = await handler(event);

      expect(result.systemPrompt).toContain("existing prompt");
      expect(result.systemPrompt).toContain("# Cyber Workflow");
      expect(result.systemPrompt).toContain("Evidence-First Doctrine");
      expect(result.systemPrompt).not.toContain("<casefile_context>");
    } finally {
      if (previous === undefined) delete process.env.PI_XP_MODE;
      else process.env.PI_XP_MODE = previous;
    }
  });

  test("XP mode on + subagent child process: before_agent_start injects nothing", async () => {
    const previousXp = process.env.PI_XP_MODE;
    const previousChild = process.env.PI_SUBAGENT_CHILD;
    process.env.PI_XP_MODE = "on";
    process.env.PI_SUBAGENT_CHILD = "1";
    try {
      const pi = createFakePi();
      casefileExtension(pi as any);

      const handler = pi.events.get("before_agent_start")?.[0];
      expect(handler).toBeFunction();
      const result = await handler({ systemPrompt: "existing prompt" });
      expect(result).toBeUndefined();
    } finally {
      if (previousXp === undefined) delete process.env.PI_XP_MODE;
      else process.env.PI_XP_MODE = previousXp;
      if (previousChild === undefined) delete process.env.PI_SUBAGENT_CHILD;
      else process.env.PI_SUBAGENT_CHILD = previousChild;
    }
  });

  test("XP toggle off→on mid-session re-injects the workflow", async () => {
    const previous = process.env.PI_XP_MODE;
    delete process.env.PI_XP_MODE;
    try {
      const pi = createFakePi();
      casefileExtension(pi as any);

      const handler = pi.events.get("before_agent_start")?.[0];
      const xpCmd = pi.commands.get("xp");
      const notify = () => undefined;

      // Default off: nothing injected.
      expect(await handler({ systemPrompt: "p" })).toBeUndefined();

      // /xp on → workflow injected.
      await xpCmd.handler("on", { ui: { notify } });
      const on1 = await handler({ systemPrompt: "p" });
      expect(on1.systemPrompt).toContain("# Cyber Workflow");

      // /xp off → nothing injected.
      await xpCmd.handler("off", { ui: { notify } });
      expect(await handler({ systemPrompt: "p" })).toBeUndefined();

      // /xp on again → workflow must come back (regression: workflowInjected
      // stayed true from the first enable, so re-enabling silently never
      // re-injected the workflow until process restart).
      await xpCmd.handler("on", { ui: { notify } });
      const on2 = await handler({ systemPrompt: "p" });
      expect(on2.systemPrompt).toContain("# Cyber Workflow");
    } finally {
      if (previous === undefined) delete process.env.PI_XP_MODE;
      else process.env.PI_XP_MODE = previous;
    }
  });

  test("XP mode on: workflow injected once per session, case list refreshes per prompt", async () => {
    const previous = process.env.PI_XP_MODE;
    process.env.PI_XP_MODE = "on";
    try {
      const pi = createFakePi();
      casefileExtension(pi as any);

      const handler = pi.events.get("before_agent_start")?.[0];
      expect(handler).toBeFunction();

      // First prompt: workflow included.
      const first = await handler({ systemPrompt: "p" });
      expect(first.systemPrompt).toContain("# Cyber Workflow");

      // Second prompt with empty ledger: no workflow, no injection at all.
      const second = await handler({ systemPrompt: "p" });
      expect(second).toBeUndefined();

      // Third prompt after a case appears: case list refreshes, workflow NOT re-injected.
      await addCase(pi, {
        title: "Mid session lead",
        status: "hypothesis",
      });
      const third = await handler({ systemPrompt: "p" });
      expect(third.systemPrompt).toContain("<casefile_context>");
      expect(third.systemPrompt).toContain("Mid session lead");
      expect(third.systemPrompt).not.toContain("# Cyber Workflow");
    } finally {
      if (previous === undefined) delete process.env.PI_XP_MODE;
      else process.env.PI_XP_MODE = previous;
    }
  });

  test("XP mode on: injects only active cases into before_agent_start context", async () => {
    const previous = process.env.PI_XP_MODE;
    process.env.PI_XP_MODE = "on";
    try {
      const pi = createFakePi();
      casefileExtension(pi as any);

      await addCase(pi, {
        title: "Active <payload> lead",
        status: "investigating",
        summary: "This should not be injected",
        evidence: "Observed suspicious response",
        confidence: "low",
        nextStep: "Test <payload> safely",
      });
      const killed = await addCase(pi, {
        title: "Killed duplicate",
        status: "investigating",
        evidence: "Duplicate",
        confidence: "low",
      });
      // Killing an investigating case now requires ARTIFACT-BACKED refutation
      // evidence (a keyword or prose-only item is not enough once the case
      // advanced past hypothesis).
      await executeTool(pi, "EvidenceAdd", {
        case_id: killed.details.record.id,
        role: "refutation",
        summary: "Re-checked: this lead duplicates an existing case; no new evidence.",
        artifact_path: observationArtifactPath,
      });
      await executeTool(pi, "CaseUpdate", {
        id: killed.details.record.id,
        status: "killed",
        assumptions: ["Duplicate lead with no new evidence"],
      });
      const reported = await addCase(pi, {
        title: "Already reported",
        status: "investigating",
        evidence: "Resolved finding",
        confidence: "high",
        poc: "Reproduced before patch",
        impact: "Was exploitable",
        severity: "high",
        target: "example-app",
        disconfirmation: "Confirmed patch blocks the path; pre-patch version still vulnerable.",
        remediation: "Patch shipped",
      });
      await executeTool(pi, "PromoteFinding", {
        id: reported.details.record.id,
        poc_path: pocScriptPath,
        verification_marker: "ok",
        control_path: controlScriptPath,
        control_liveness_marker: "CONTROL_REACHED_1",
        disconfirmation_path: disconfirmationScriptPath,
        local: true,
      });
      const ctxResult = await executeTool(pi, "CaseContext", { id: reported.details.record.id });
      // The reporter agent writes the report file (passing the content gate:
      // non-trivial size, required sections, no internal identifiers) before
      // the case flips to reported.
      writeFileSync(
        ctxResult.details.path,
        `# Already reported\n\n## Summary\nThe finding was resolved before reporting; pre-patch versions were vulnerable.\n\n## Vulnerability Details\nThe export endpoint allowed unauthorized access to resources.\n\n## Steps to Reproduce\n1. Authenticate as a regular user.\n2. Request a resource owned by another user.\n\n## Impact\nUnauthorized disclosure of resources; now patched.\n\n## Remediation\nPatch shipped; the endpoint now enforces ownership checks.\n`,
        "utf8",
      );
      await executeTool(pi, "CaseUpdate", {
        id: reported.details.record.id,
        status: "reported",
        remediation: "Patch shipped",
      });

      const handler = pi.events.get("before_agent_start")?.[0];
      expect(handler).toBeFunction();

      const event = { systemPrompt: "" };
      const result = await handler(event);
      expect(result.systemPrompt).toContain("Active security cases: 1 total");
      expect(result.systemPrompt).toContain("Active ‹payload› lead");
      expect(result.systemPrompt).toContain("Test ‹payload› safely");
      expect(result.systemPrompt).not.toContain("This should not be injected");
      expect(result.systemPrompt).not.toContain("Killed duplicate");
      expect(result.systemPrompt).not.toContain("Already reported");
      // Workflow still rides along with the case list.
      expect(result.systemPrompt).toContain("# Cyber Workflow");
    } finally {
      if (previous === undefined) delete process.env.PI_XP_MODE;
      else process.env.PI_XP_MODE = previous;
    }
  });

  test("XP mode on: includes hypothesis and blocked cases in prompt context", async () => {
    const previous = process.env.PI_XP_MODE;
    process.env.PI_XP_MODE = "on";
    try {
      const pi = createFakePi();
      casefileExtension(pi as any);

      await addCase(pi, {
        title: "Hypothesis lead",
        status: "hypothesis",
      });
      const blocked = await addCase(pi, {
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
      const event = { systemPrompt: "" };
      const result = await handler(event);

      expect(result.systemPrompt).toContain("Hypothesis lead");
      expect(result.systemPrompt).toContain("Blocked lead");
    } finally {
      if (previous === undefined) delete process.env.PI_XP_MODE;
      else process.env.PI_XP_MODE = previous;
    }
  });

  test("injects at most 20 active cases, P0 first, with +N more hint", async () => {
    const previous = process.env.PI_XP_MODE;
    process.env.PI_XP_MODE = "on";
    try {
      const pi = createFakePi();
      casefileExtension(pi as any);

      // 21 hypotheses: one P0, twenty P4 — the cap must drop exactly one.
      const ids: string[] = [];
      let p0Id = "";
      for (let i = 0; i < 21; i++) {
        const res = await addCase(pi, {
          title: `Coverage candidate number ${i}`,
          status: "hypothesis",
          evidence: "probe",
          priority: i === 0 ? "P0" : "P4",
        });
        ids.push(res.details.record.id);
        if (i === 0) p0Id = res.details.record.id;
      }

      const handler = pi.events.get("before_agent_start")?.[0];
      const result = await handler({ systemPrompt: "" });
      const ctx = result.systemPrompt;

      expect(ctx).toContain("Active security cases: 21 total");
      expect(ctx).toContain("+1 more cases — use CaseList for the rest.");

      // Exactly 20 of the 21 ids are injected (the cap dropped one).
      const present = ids.filter((id) => ctx.includes(id));
      expect(present.length).toBe(20);

      // Priority sort: the P0 case is the FIRST listed case row.
      const firstRowStart = ctx.indexOf("  - case_");
      const firstRow = ctx.slice(firstRowStart, ctx.indexOf("\n", firstRowStart));
      expect(firstRow).toContain(p0Id);
    } finally {
      if (previous === undefined) delete process.env.PI_XP_MODE;
      else process.env.PI_XP_MODE = previous;
    }
  });

  test("workflow constants carry the new gates and the renamed tool (no stale CaseReport)", () => {
    // The injected text is the operative contract; dropping a gate or the
    // renamed tool silently passes the injection tests, so pin the markers.
    expect(STATIC_CYBER_WORKFLOW).toContain("Design & Runtime Check");
    expect(STATIC_CYBER_WORKFLOW).toContain("CaseContext");
    expect(STATIC_CYBER_WORKFLOW).not.toContain("CaseReport");
    expect(STATIC_CYBER_WORKFLOW).toContain('agent: "reporter"');
    expect(STATIC_CYBER_WORKFLOW_LITE).toContain("Report style checklist");
    expect(STATIC_CYBER_WORKFLOW_LITE).toContain("CaseContext");
    expect(STATIC_CYBER_WORKFLOW_LITE).not.toContain("CaseReport");
  });

  test("/xp command toggles mode and gates injection", async () => {
    const previous = process.env.PI_XP_MODE;
    delete process.env.PI_XP_MODE;
    try {
      const pi = createFakePi();
      casefileExtension(pi as any);
      const notifications: string[] = [];
      const ctx = {
        hasUI: false,
        ui: {
          notify: (message: string) => notifications.push(message),
          setStatus: () => {},
        },
      };

      const handler = pi.events.get("before_agent_start")?.[0];
      expect(await handler()).toBeUndefined();

      await pi.commands.get("xp").handler("on", ctx);
      expect(notifications.some((n) => n.includes("ON"))).toBe(true);
      const event = { systemPrompt: "" };
      const onResult = await handler(event);
      expect(onResult.systemPrompt).toContain("# Cyber Workflow");

      await pi.commands.get("xp").handler("off", ctx);
      expect(await handler()).toBeUndefined();
    } finally {
      if (previous === undefined) delete process.env.PI_XP_MODE;
      else process.env.PI_XP_MODE = previous;
    }
  });

  test("/xp lite sets lite mode and injects the lite workflow", async () => {
    const previous = process.env.PI_XP_MODE;
    delete process.env.PI_XP_MODE;
    try {
      const pi = createFakePi();
      casefileExtension(pi as any);
      const notifications: string[] = [];
      const ctx = {
        hasUI: false,
        ui: {
          notify: (message: string) => notifications.push(message),
          setStatus: () => {},
        },
      };

      await pi.commands.get("xp").handler("lite", ctx);
      expect(notifications.some((n) => n.includes("LITE"))).toBe(true);

      const handler = pi.events.get("before_agent_start")?.[0];
      expect(handler).toBeFunction();
      const result = await handler({ systemPrompt: "" });
      expect(result.systemPrompt).toContain("# Cyber Workflow — LITE (Single-Agent)");
      expect(result.systemPrompt).not.toContain("Evidence-First Doctrine");
    } finally {
      if (previous === undefined) delete process.env.PI_XP_MODE;
      else process.env.PI_XP_MODE = previous;
    }
  });

  test("supports the non-ui dashboard command and status updates", async () => {
    const pi = createFakePi();
    casefileExtension(pi as any);

    const storedXss = await addCase(pi, {
      title: "Stored XSS",
      status: "investigating",
      evidence: "Payload renders in notes",
      confidence: "high",
      poc: "Render a note containing <img src=x onerror=alert(1)> and observe execution",
      impact: "Script execution in victim browser",
      severity: "high",
      target: "example-app",
      disconfirmation:
        "Attempted to render note without script content; no execution occurred. Only script-tagged content triggers.",
    });
    await executeTool(pi, "PromoteFinding", {
      id: storedXss.details.record.id,
      poc_path: pocScriptPath,
      verification_marker: "ok",
      control_path: controlScriptPath,
      control_liveness_marker: "CONTROL_REACHED_1",
      disconfirmation_path: disconfirmationScriptPath,
      local: true,
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
