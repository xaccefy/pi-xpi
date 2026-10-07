import { afterEach, beforeEach, describe, expect, mock, test } from "bun:test";
import { readFileSync, writeFileSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setHarnessFetchForTest } from "../src/harness-verify.ts";
import { getCaseById, setCasefilePath } from "../src/ledger.ts";
import { setOobOracleFetchForTest } from "../src/oob-oracle.ts";
import { setScratchpadRoot } from "../src/scratchpad.ts";
import {
  STATIC_CYBER_WORKFLOW,
  STATIC_CYBER_WORKFLOW_LITE,
  STATIC_CYBER_WORKFLOW_OMP,
} from "../src/workflow.ts";

mock.module("@earendil-works/pi-ai", () => ({
  StringEnum: (values: readonly string[]) => ({ enum: values }),
}));

mock.module("typebox", () => ({
  Type: {
    Array: (item: unknown, options?: Record<string, unknown>) => ({ item, ...options }),
    Boolean: (options?: Record<string, unknown>) => ({ type: "boolean", ...options }),
    Integer: (options?: Record<string, unknown>) => ({ type: "integer", ...options }),
    Literal: (value: unknown, options?: Record<string, unknown>) => ({ const: value, ...options }),
    Number: (options?: Record<string, unknown>) => ({ type: "number", ...options }),
    Object: (properties: Record<string, unknown>, options?: Record<string, unknown>) => ({
      type: "object",
      properties,
      ...options,
    }),
    Optional: (schema: unknown) => schema,
    String: (options?: Record<string, unknown>) => ({ type: "string", ...options }),
    Union: (items: unknown[], options?: Record<string, unknown>) => ({ anyOf: items, ...options }),
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
const nativeFetch = globalThis.fetch;

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
  const finalParams = params;
  try {
    return await tool.execute(
      "test-call",
      finalParams,
      new AbortController().signal,
      () => undefined,
      {},
    );
  } catch (error) {
    if (name !== "PromoteFinding") throw error;
    const text = (error as Error).message;
    return {
      content: [{ type: "text", text }],
      isError: true,
      details: {
        record: typeof finalParams.id === "string" ? getCaseById(finalParams.id) : undefined,
        missingPocPath: text.includes("poc_path is REQUIRED"),
        missingControlTarget: text.includes("control_target is REQUIRED"),
        controlTargetEqualsCase: text.includes("control_target must differ from the case target"),
        controlNotAuthorized: text.includes("CONTROL AUTHORIZATION FAILED"),
        evidenceFailed: text.includes("EVIDENCE CONTRACT FAILED"),
        controlIdentical: text.includes("identical evidence to the target"),
        controlBindingFailed: text.includes("CONTROL BINDING FAILED"),
        didNotComplete: /did not complete|did NOT complete/i.test(text),
        sameFileCheckFailed: text.includes("sha256 mismatch"),
      },
    };
  }
}

beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), "casefile-index-test-"));
  setCasefilePath(join(tempDir, "casefile.db"));
  setScratchpadRoot(tempDir);
  pocScriptPath = join(tempDir, "shared.sh");
  // Same-file contract: the control must be the SAME script as the PoC
  // (sha256-equal; the only permitted difference is PI_POC_MODE). The shared
  // fixture writes nonce-bound evidence.json per run, with mode-dependent
  // content: the target run claims the vuln, the control run claims the
  // baseline (so the machine differential passes).
  writeFileSync(
    pocScriptPath,
    [
      "#!/bin/sh",
      'E="$PI_POC_EVIDENCE_DIR"',
      'mkdir -p "$E"',
      'T="$PI_POC_TARGET"',
      'case "$T" in http://*|https://*) ;; *) T="http://$T" ;; esac',
      'if [ "$PI_POC_MODE" = "control" ]; then',
      '  printf \'{"nonce":"%s","claim":"control baseline lacks the vuln","verify":{"method":"GET","url":"%s/read?file=/etc/passwd","expect":{"status":[403],"body_contains":["not vulnerable"]}},"observations":["control returned 403"]}\' "$PI_POC_NONCE" "$T" > "$E/evidence.json"',
      "  exit 0",
      "fi",
      'printf \'{"nonce":"%s","claim":"read /etc/passwd of target","verify":{"method":"GET","url":"%s/read?file=/etc/passwd","expect":{"status":[200],"body_contains":["root:"]}},"observations":["root: present"]}\' "$PI_POC_NONCE" "$T" > "$E/evidence.json"',
      "printf 'ok'",
      "exit 0",
      "",
    ].join("\n"),
    "utf8",
  );
  controlScriptPath = pocScriptPath;
  observationArtifactPath = join(tempDir, "observation.txt");
  writeFileSync(observationArtifactPath, "observed signal (fixture)", "utf8");
  disconfirmationScriptPath = join(tempDir, "disconf.sh");
  writeFileSync(disconfirmationScriptPath, "#!/bin/sh\nexit 1", "utf8");
  process.env.PI_POC_ROOT = tempDir;
  process.env.CASEFILE_WORKSPACE_ROOT = tempDir;
  // Local (host) execution is operator-gated; the test harness FORCE_LOCAL
  // so promote tests run hermetically without Docker even when Docker is
  // installed — production still prefers the host-network sandbox.
  process.env.PI_POC_ALLOW_LOCAL = "1";
  process.env.PI_POC_FORCE_LOCAL = "1";
  process.env.PI_POC_ALLOW_NETWORK = "1";
  process.env.PI_POC_ALLOW_PRIVATE_REPLAY = "1";
  process.env.PI_POC_CONTROL_TARGETS = "https://control.example,example-app";
  globalThis.fetch = (async (input: string | URL | Request) => {
    const url = new URL(String(input));
    return url.hostname.includes("control")
      ? new Response("not vulnerable", { status: 403 })
      : new Response("root:x:0:0:root:/root:/bin/sh", { status: 200 });
  }) as typeof fetch;
  setHarnessFetchForTest(globalThis.fetch as unknown as (input: string | URL) => Promise<Response>);
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
  delete process.env.CASEFILE_WORKSPACE_ROOT;
  delete process.env.PI_POC_ALLOW_LOCAL;
  delete process.env.PI_POC_FORCE_LOCAL;
  delete process.env.PI_POC_ALLOW_NETWORK;
  delete process.env.PI_POC_ALLOW_PRIVATE_REPLAY;
  delete process.env.PI_POC_CONTROL_TARGETS;
  delete process.env.PI_SUBAGENT_CHILD;
  delete process.env.PI_OOB_ORACLE_URL;
  delete process.env.PI_OOB_ORACLE_TOKEN;
  delete process.env.PI_OOB_SOURCE_SEPARATED;
  delete process.env.PI_OOB_SELF_IPS;
  delete process.env.PI_OOB_POLL_MS;
  delete process.env.PI_OOB_INTERVAL_MS;
  delete process.env.PI_OOB_SETTLE_MS;
  setHarnessFetchForTest(undefined);
  setOobOracleFetchForTest(undefined);
  globalThis.fetch = nativeFetch;
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
      "ConfirmFinding",
      "CoverageAdd",
      "CoverageReport",
      "EvidenceAdd",
      "Objective",
      "PipelineSubmit",
      "Primitive",
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

  test("does not register validation gates when a worker unsets its role after startup", () => {
    process.env.PI_SUBAGENT_CHILD = "1";
    try {
      const pi = createFakePi();
      casefileExtension(pi as any);
      delete process.env.PI_SUBAGENT_CHILD;
      expect(pi.tools.has("ConfirmFinding")).toBe(false);
      expect(pi.tools.has("PromoteFinding")).toBe(false);
    } finally {
      delete process.env.PI_SUBAGENT_CHILD;
    }
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

    // Phase 1: PromoteFinding records the evidence bundle (2 target runs +
    // control); the case stays investigating until main-agent review.
    const phase1 = await executeTool(pi, "PromoteFinding", {
      id: record.id,
      poc_path: pocScriptPath,
      control_target: "https://control.example",
      control_path: controlScriptPath,
      local: true,
    });
    expect(phase1.details?.record?.status).toBe("investigating");
    expect(phase1.details.record.pendingConfirmation).toBeDefined();
    expect(phase1.details.bundle.evidenceSha256).toMatch(/^[a-f0-9]{64}$/);

    // Phase 2: ConfirmFinding commits the main agent's complete verdict.
    const promoted = await executeTool(pi, "ConfirmFinding", {
      id: record.id,
      verdict: {
        verdict: "CONFIRMED",
        reasoning: "re-sent the verify request: target returned the claimed entry, control did not",
        evidence_reviewed: ["evidence.json (target run 1)", "evidence.json (control run)"],
        re_execution_note: "GET /read?file=/etc/passwd → 200 with root: on target; 403 on control",
        differential: "target_only",
        severity_match: "ok",
        disconfirmation_attempt:
          "tried /read?file=/etc/shadow and a patched replica → no entry; the effect is target-dependent",
        canary_assessment: "not_applicable",
        canary_reason: "file-read output has no attacker-reflected field",
        model: "test-model",
      },
    });
    expect(promoted.details.promoted).toBe(true);
    expect(promoted.details.record.status).toBe("confirmed");
    expect(promoted.details.record.confirmerVerdict?.reviewer).toBe("main_agent");
    expect(promoted.details.record.confirmerVerdict?.phase2Verification?.result.differential).toBe(
      "target_only",
    );
    expect(promoted.details.record.pocVerified?.exitCode).toBe(0);
    expect(promoted.details.record.evidence).toContain("PoC Execution Capture");
    expect(promoted.details.record.evidence).toContain("Target Run Output");
    // The main agent's attempt becomes the case's disconfirmation.
    expect(promoted.details.record.disconfirmation).toContain("tried /read?file=/etc/shadow");
    // The reproduction evidence item is artifact-backed by the preserved copy.
    const repro = promoted.details.record.evidenceItems?.find(
      (e: { role: string }) => e.role === "reproduction",
    );
    expect(repro).toBeDefined();
    expect(repro.artifactPath).toMatch(/\.evidence\.json$/);

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
    // context bundle; the report path is reserved for the main agent's final report.
    const contextText = readFileSync(report.details.contextPath, "utf8");
    expect(contextText).toContain("PoC Verification Log");
    expect(contextText).toContain("Output\n```\nok\n```");
    expect(contextText).toContain("Complete Case Record");
    expect(contextText).toContain("Linked Cases");
  });

  test("PromoteFinding oob:true fails closed without an operator-configured oracle", async () => {
    const pi = createFakePi();
    casefileExtension(pi as any);
    const added = await addCase(pi, {
      title: "OOB without network",
      status: "investigating",
      evidence: "blind SSRF suspected",
      confidence: "high",
      severity: "high",
      poc: "send callback payload",
      impact: "internal fetch",
      target: "oob-app",
    });
    const phase1 = await executeTool(pi, "PromoteFinding", {
      id: added.details.record.id,
      poc_path: pocScriptPath,
      control_path: controlScriptPath,
      control_target: "https://control.example",
      oob: true,
    });
    expect(phase1.isError).toBe(true);
    expect(phase1.content[0].text).toContain("PI_OOB_ORACLE_URL");
    expect(phase1.details.record.pendingConfirmation).toBeUndefined();
  });

  test("PromoteFinding oob:true records an honest oracle differential (target token only)", async () => {
    const pi = createFakePi();
    casefileExtension(pi as any);
    // Mock operator oracle: first-provisioned token = target run; the TARGET
    // (and only the target) causes one interaction with it.
    const provisioned: string[] = [];
    setOobOracleFetchForTest(async (url: string, init?: RequestInit) => {
      const u = new URL(url);
      if (u.pathname === "/provision") {
        const body = JSON.parse(String(init?.body ?? "{}")) as { token: string };
        provisioned.push(body.token);
        return new Response(JSON.stringify({ domain: `${body.token}.oob.test` }), { status: 200 });
      }
      if (u.pathname === "/interactions") {
        const token = u.searchParams.get("token") ?? "";
        const hits = token === provisioned[0] && !token.includes(provisioned[1] ?? "") ? 1 : 0;
        const interactions = hits
          ? [{ protocol: "dns", src_ip: "203.0.113.7", ts: new Date().toISOString(), raw: "" }]
          : [];
        return new Response(JSON.stringify({ interactions }), { status: 200 });
      }
      return new Response("not found", { status: 404 });
    });
    process.env.PI_OOB_ORACLE_URL = "http://oob.test";
    process.env.PI_OOB_SOURCE_SEPARATED = "1";
    process.env.PI_OOB_POLL_MS = "600";
    process.env.PI_OOB_INTERVAL_MS = "100";
    process.env.PI_OOB_SETTLE_MS = "250";
    try {
      const added = await addCase(pi, {
        title: "Blind SSRF honest",
        status: "investigating",
        evidence: "URL param fetched server-side",
        confidence: "high",
        severity: "high",
        poc: "make target fetch callback domain",
        impact: "internal fetch",
        target: "oob-app",
      });
      const phase1 = await executeTool(pi, "PromoteFinding", {
        id: added.details.record.id,
        poc_path: pocScriptPath,
        oob: true,
      });
      expect(phase1.isError).toBeUndefined();
      const bundle = phase1.details.record.pendingConfirmation;
      expect(bundle).toBeDefined();
      expect(bundle.callbackVerified.attempted).toBe(true);
      expect(bundle.callbackVerified.targetHits).toBe(1);
      expect(bundle.callbackVerified.controlHits).toBe(0);
      expect(bundle.callbackVerified.sourceSeparated).toBe(true);

      // Phase 2 must NOT require a control target for OOB-only bundles — it
      // re-polls the oracle freshly and commits on the same differential.
      const confirm = await executeTool(pi, "ConfirmFinding", {
        id: added.details.record.id,
        verdict: {
          verdict: "CONFIRMED",
          reasoning: "oracle saw the target token only under attested source separation",
          evidence_reviewed: ["poc"],
          differential: "target_only",
          re_execution_note: "fresh harness re-poll observed the same target-only differential",
          disconfirmation_attempt:
            "serial baseline and patched-control reasoning both fail to explain the callback",
          canary_assessment: "not_applicable",
          canary_reason: "the per-run OOB token IS the causality signal here",
        },
      });
      expect(confirm.details.promoted).toBe(true);
    } finally {
      delete process.env.PI_OOB_ORACLE_URL;
      delete process.env.PI_OOB_SOURCE_SEPARATED;
      delete process.env.PI_OOB_POLL_MS;
      delete process.env.PI_OOB_INTERVAL_MS;
      delete process.env.PI_OOB_SETTLE_MS;
      setOobOracleFetchForTest(undefined);
    }
  });

  test("PromoteFinding oob:true rejects a bundle whose control token also fired", async () => {
    const pi = createFakePi();
    casefileExtension(pi as any);
    // Cheating topology: BOTH tokens receive interactions — not target-dependent.
    const provisioned: string[] = [];
    setOobOracleFetchForTest(async (url: string, init?: RequestInit) => {
      const u = new URL(url);
      if (u.pathname === "/provision") {
        const body = JSON.parse(String(init?.body ?? "{}")) as { token: string };
        provisioned.push(body.token);
        return new Response(JSON.stringify({ domain: `${body.token}.oob.test` }), { status: 200 });
      }
      if (u.pathname === "/interactions") {
        return new Response(
          JSON.stringify({
            interactions: [{ protocol: "dns", src_ip: "203.0.113.7", ts: "", raw: "" }],
          }),
          { status: 200 },
        );
      }
      return new Response("not found", { status: 404 });
    });
    process.env.PI_OOB_ORACLE_URL = "http://oob.test";
    process.env.PI_OOB_SOURCE_SEPARATED = "1";
    process.env.PI_OOB_POLL_MS = "600";
    process.env.PI_OOB_INTERVAL_MS = "100";
    process.env.PI_OOB_SETTLE_MS = "250";
    try {
      const added = await addCase(pi, {
        title: "Cheating callback",
        status: "investigating",
        evidence: "suspected SSRF",
        confidence: "high",
        severity: "high",
        poc: "curl callback unconditionally",
        impact: "internal fetch",
        target: "oob-app",
      });
      const phase1 = await executeTool(pi, "PromoteFinding", {
        id: added.details.record.id,
        poc_path: pocScriptPath,
        oob: true,
      });
      // The gate rejects at store time: control-token interactions mean the
      // callback is not target-dependent.
      expect(phase1.isError).toBe(true);
      expect(phase1.content[0].text).toContain("OOB VERIFY FAILED");
      expect(phase1.content[0].text).toContain("not target-dependent");
      expect(phase1.details.record.pendingConfirmation).toBeUndefined();
    } finally {
      for (const k of [
        "PI_OOB_ORACLE_URL",
        "PI_OOB_SOURCE_SEPARATED",
        "PI_OOB_POLL_MS",
        "PI_OOB_INTERVAL_MS",
        "PI_OOB_SETTLE_MS",
      ])
        delete process.env[k];
      setOobOracleFetchForTest(undefined);
    }
  });

  test("OOB polling keeps watching after the first hit so delayed control hits are caught", async () => {
    const pi = createFakePi();
    casefileExtension(pi as any);
    let pollCount = 0;
    const provisioned: string[] = [];
    setOobOracleFetchForTest(async (url: string, init?: RequestInit) => {
      const u = new URL(url);
      if (u.pathname === "/provision") {
        const body = JSON.parse(String(init?.body ?? "{}")) as { token: string };
        provisioned.push(body.token);
        return new Response(JSON.stringify({ domain: `${body.token}.oob.test` }), { status: 200 });
      }
      if (u.pathname === "/interactions") {
        pollCount += 1;
        const token = u.searchParams.get("token") ?? "";
        // Target token fires immediately; the CONTROL token only fires on a
        // LATER poll — an early break would miss it and pass a cheater.
        if (token === provisioned[0]) {
          return new Response(
            JSON.stringify({ interactions: [{ protocol: "dns", src_ip: "203.0.113.7" }] }),
            { status: 200 },
          );
        }
        const lateControl = pollCount >= 4;
        return new Response(
          JSON.stringify({
            interactions: lateControl ? [{ protocol: "dns", src_ip: "203.0.113.9" }] : [],
          }),
          { status: 200 },
        );
      }
      return new Response("not found", { status: 404 });
    });
    process.env.PI_OOB_ORACLE_URL = "http://oob.test";
    process.env.PI_OOB_SOURCE_SEPARATED = "1";
    process.env.PI_OOB_POLL_MS = "5000";
    process.env.PI_OOB_INTERVAL_MS = "100";
    process.env.PI_OOB_SETTLE_MS = "800";
    try {
      const added = await addCase(pi, {
        title: "Late control hit",
        status: "investigating",
        evidence: "suspected SSRF",
        confidence: "high",
        severity: "high",
        poc: "trigger",
        impact: "fetch",
        target: "oob-app",
      });
      const phase1 = await executeTool(pi, "PromoteFinding", {
        id: added.details.record.id,
        poc_path: pocScriptPath,
        oob: true,
      });
      expect(phase1.isError).toBe(true);
      expect(phase1.content[0].text).toContain("not target-dependent");
    } finally {
      for (const k of [
        "PI_OOB_ORACLE_URL",
        "PI_OOB_SOURCE_SEPARATED",
        "PI_OOB_POLL_MS",
        "PI_OOB_INTERVAL_MS",
        "PI_OOB_SETTLE_MS",
      ])
        delete process.env[k];
      setOobOracleFetchForTest(undefined);
    }
  }, 10_000);

  test("unattributed interactions (missing src_ip) never count as target hits", async () => {
    const pi = createFakePi();
    casefileExtension(pi as any);
    const provisioned: string[] = [];
    setOobOracleFetchForTest(async (url: string, init?: RequestInit) => {
      const u = new URL(url);
      if (u.pathname === "/provision") {
        const body = JSON.parse(String(init?.body ?? "{}")) as { token: string };
        provisioned.push(body.token);
        return new Response(JSON.stringify({ domain: `${body.token}.oob.test` }), { status: 200 });
      }
      if (u.pathname === "/interactions") {
        const token = u.searchParams.get("token") ?? "";
        // A fabricated-looking interaction with NO src_ip must be rejected.
        const interactions =
          token === provisioned[0] ? [{ protocol: "http", raw: "fabricated?" }] : [];
        return new Response(JSON.stringify({ interactions }), { status: 200 });
      }
      return new Response("not found", { status: 404 });
    });
    process.env.PI_OOB_ORACLE_URL = "http://oob.test";
    process.env.PI_OOB_SOURCE_SEPARATED = "1";
    process.env.PI_OOB_POLL_MS = "600";
    process.env.PI_OOB_INTERVAL_MS = "100";
    process.env.PI_OOB_SETTLE_MS = "250";
    try {
      const added = await addCase(pi, {
        title: "Unattributed callback",
        status: "investigating",
        evidence: "suspected SSRF",
        confidence: "high",
        severity: "high",
        poc: "trigger",
        impact: "fetch",
        target: "oob-app",
      });
      const phase1 = await executeTool(pi, "PromoteFinding", {
        id: added.details.record.id,
        poc_path: pocScriptPath,
        oob: true,
      });
      expect(phase1.isError).toBe(true);
      expect(phase1.content[0].text).toContain("no interaction with the target-run callback token");
    } finally {
      for (const k of [
        "PI_OOB_ORACLE_URL",
        "PI_OOB_SOURCE_SEPARATED",
        "PI_OOB_POLL_MS",
        "PI_OOB_INTERVAL_MS",
        "PI_OOB_SETTLE_MS",
      ])
        delete process.env[k];
      setOobOracleFetchForTest(undefined);
    }
  });

  test("mode:'intra_target' combined with oob:true is rejected", async () => {
    const pi = createFakePi();
    casefileExtension(pi as any);
    process.env.PI_OOB_ORACLE_URL = "http://oob.test";
    try {
      const added = await addCase(pi, {
        title: "Intra OOB conflict",
        status: "investigating",
        evidence: "x",
        confidence: "high",
        severity: "high",
        poc: "p",
        impact: "i",
        target: "oob-app",
      });
      const phase1 = await executeTool(pi, "PromoteFinding", {
        id: added.details.record.id,
        poc_path: pocScriptPath,
        mode: "intra_target",
        oob: true,
      });
      expect(phase1.isError).toBe(true);
      expect(phase1.content[0].text).toContain("cannot be combined with oob:true");
    } finally {
      delete process.env.PI_OOB_ORACLE_URL;
    }
  });

  test("oob:true + reflection canary in evidence is rejected with a clear message", async () => {
    const pi = createFakePi();
    casefileExtension(pi as any);
    // Oracle configured so the run gets past provisioning; the canary lives
    // in the PoC's evidence.json, so rejection happens after run 1.
    setOobOracleFetchForTest(async (url: string, init?: RequestInit) => {
      const u = new URL(url);
      if (u.pathname === "/provision") {
        const body = JSON.parse(String(init?.body ?? "{}")) as { token: string };
        return new Response(JSON.stringify({ domain: `${body.token}.oob.test` }), { status: 200 });
      }
      return new Response(JSON.stringify({ interactions: [] }), { status: 200 });
    });
    process.env.PI_OOB_ORACLE_URL = "http://oob.test";
    try {
      const added = await addCase(pi, {
        title: "Canary plus OOB",
        status: "investigating",
        evidence: "x",
        confidence: "high",
        severity: "high",
        poc: "p",
        impact: "i",
        target: "oob-app",
      });
      // PoC whose evidence declares a reflection canary.
      const canaryPoc = join(tempDir, "canary-oob.sh");
      writeFileSync(
        canaryPoc,
        [
          "#!/bin/sh",
          'E="$PI_POC_EVIDENCE_DIR"',
          'mkdir -p "$E"',
          'printf \'{"nonce":"%s","claim":"c","verify":{"method":"GET","url":"http://oob-app/x?c={{PI_POC_CANARY}}","expect":{"status":[200],"body_contains":["resp"]},"canary":{"mode":"reflection","placeholder":"{{PI_POC_CANARY}}"}},"observations":[]}\' "$PI_POC_NONCE" > "$E/evidence.json"',
          "exit 0",
          "",
        ].join("\n"),
        "utf8",
      );
      const phase1 = await executeTool(pi, "PromoteFinding", {
        id: added.details.record.id,
        poc_path: canaryPoc,
        oob: true,
      });
      expect(phase1.isError).toBe(true);
      expect(phase1.content[0].text).toContain("cannot be combined with oob:true");
      expect(phase1.details.record.pendingConfirmation).toBeUndefined();
    } finally {
      delete process.env.PI_OOB_ORACLE_URL;
      setOobOracleFetchForTest(undefined);
    }
  });

  test("PromoteFinding defaults control_path to poc_path but still requires an approved control target", async () => {
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
    });
    const id = added.details.record.id;

    // Missing control_path is no longer ceremony: the harness defaults it to
    // poc_path, then still runs the same-byte control branch.
    const defaultControlPath = await executeTool(pi, "PromoteFinding", {
      id,
      poc_path: pocScriptPath,
      control_target: "https://control.example",
      local: true,
    });
    expect(defaultControlPath.isError).toBeUndefined();
    expect(defaultControlPath.details.record.status).toBe("investigating");
    expect(defaultControlPath.details.record.pendingConfirmation.controlPath).toBe(pocScriptPath);

    // control_target is still mandatory and cannot be inferred by the agent.
    const noTargetFromDefault = await executeTool(pi, "PromoteFinding", {
      id,
      poc_path: pocScriptPath,
      local: true,
    });
    expect(noTargetFromDefault.isError).toBe(true);
    expect(noTargetFromDefault.details.missingControlTarget).toBe(true);
    expect(noTargetFromDefault.details.record.status).toBe("investigating");

    // control_path without control_target — blocked before any PoC run.
    const noTarget = await executeTool(pi, "PromoteFinding", {
      id,
      poc_path: pocScriptPath,
      control_path: controlScriptPath,
    });
    expect(noTarget.isError).toBe(true);
    expect(noTarget.details.missingControlTarget).toBe(true);
    expect(noTarget.details.record.status).toBe("investigating");

    // control_target equal to the case target — blocked: a control run against
    // the vulnerable target proves nothing.
    const sameTarget = await executeTool(pi, "PromoteFinding", {
      id,
      poc_path: pocScriptPath,
      control_path: controlScriptPath,
      control_target: "example-app",
    });
    expect(sameTarget.isError).toBe(true);
    expect(sameTarget.details.controlTargetEqualsCase).toBe(true);
    expect(sameTarget.details.record.status).toBe("investigating");

    // A distinct but agent-invented host is not a valid control trust anchor.
    const inventedControl = await executeTool(pi, "PromoteFinding", {
      id,
      poc_path: pocScriptPath,
      control_path: controlScriptPath,
      control_target: "invented-control.example",
    });
    expect(inventedControl.isError).toBe(true);
    expect(inventedControl.details.controlNotAuthorized).toBe(true);
    expect(inventedControl.details.record.status).toBe("investigating");
  });

  test("PromoteFinding rejects a PoC that exits 0 but writes no evidence.json", async () => {
    const pi = createFakePi();
    casefileExtension(pi as any);

    const added = await addCase(pi, {
      title: "Exit 0 without evidence",
      status: "investigating",
      evidence: "reflected input",
      confidence: "high",
      severity: "high",
      poc: "send payload, check reflection",
      impact: "script execution",
      target: "example-app",
    });
    const id = added.details.record.id;

    // The script "succeeds" (exit 0) but never writes evidence.json — the old
    // exit-0 gate would have promoted it; the evidence contract blocks it.
    const noEvidence = join(tempDir, "no-evidence.sh");
    writeFileSync(noEvidence, "#!/bin/sh\nexit 0", "utf8");

    const result = await executeTool(pi, "PromoteFinding", {
      id,
      poc_path: noEvidence,
      control_target: "https://control.example",
      control_path: noEvidence,
      local: true,
    });
    expect(result.isError).toBe(true);
    expect(result.details.evidenceFailed).toBe(true);
    expect(result.details.record.status).toBe("investigating");
  });

  test("PromoteFinding blocks a control run whose evidence matches the target's (cheat)", async () => {
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
    });
    const id = added.details.record.id;

    // The control script is the SAME file as the PoC (same-file contract) but
    // its control branch writes the SAME evidence as the target branch — the
    // way a cheating PoC claims success regardless of target behavior. The
    // machine differential must block the promotion.
    const cheatScript = join(tempDir, "cheat.sh");
    writeFileSync(
      cheatScript,
      [
        "#!/bin/sh",
        'E="$PI_POC_EVIDENCE_DIR"',
        'mkdir -p "$E"',
        // Hardcoded URL + claim in BOTH modes: the control run's evidence is
        // byte-identical to the target's (modulo nonce), so the machine
        // differential must block the promotion.
        'printf \'{"nonce":"%s","claim":"read /etc/passwd","verify":{"method":"GET","url":"http://victim/read?file=/etc/passwd","expect":{"status":[200],"body_contains":["root:"]}},"observations":["root:"]}\' "$PI_POC_NONCE" > "$E/evidence.json"',
        "exit 0",
        "",
      ].join("\n"),
      "utf8",
    );

    const result = await executeTool(pi, "PromoteFinding", {
      id,
      poc_path: cheatScript,
      control_target: "https://control.example",
      control_path: cheatScript,
      local: true,
    });
    expect(result.isError).toBe(true);
    expect(result.details.controlIdentical).toBe(true);
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
    });
    const id = added.details.record.id;

    // A control script that kills itself never runs to completion — the gate
    // must NOT treat a crash as a clean control verdict. The poc branch still
    // writes valid evidence (so the failure is the CONTROL completion, not the
    // poc evidence contract). Same-file contract: poc and control are the SAME
    // script.
    const crashControl = join(tempDir, "crash-control.sh");
    writeFileSync(
      crashControl,
      [
        "#!/bin/sh",
        'E="$PI_POC_EVIDENCE_DIR"',
        'mkdir -p "$E"',
        'if [ "$PI_POC_MODE" = "control" ]; then',
        "  kill -9 $$",
        "fi",
        'printf \'{"nonce":"%s","claim":"read /etc/passwd","verify":{"method":"GET","url":"http://%s/read?file=/etc/passwd","expect":{"status":[200],"body_contains":["root:"]}},"observations":["root:"]}\' "$PI_POC_NONCE" "$PI_POC_TARGET" > "$E/evidence.json"',
        "exit 0",
        "",
      ].join("\n"),
      "utf8",
    );

    const result = await executeTool(pi, "PromoteFinding", {
      id,
      poc_path: crashControl,
      control_target: "https://control.example",
      control_path: crashControl,
      local: true,
    });
    expect(result.isError).toBe(true);
    expect(result.details.didNotComplete).toBe(true);
    expect(result.details.record.status).toBe("investigating");
  });

  test("PromoteFinding blocks a control that completes but writes no evidence", async () => {
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
    });
    const id = added.details.record.id;

    // The control exits cleanly — but it never writes evidence.json, so it
    // never demonstrates anything about the control target. A "control" that
    // completes without a verdict is not a clean verdict. Same-file contract:
    // poc and control are the SAME script (the poc branch also writes nothing).
    const deadControl = join(tempDir, "dead-control.sh");
    writeFileSync(
      deadControl,
      '#!/bin/sh\nif [ "$PI_POC_MODE" = "control" ]; then\n  exit 0\nfi\nprintf \'ok\'',
      "utf8",
    );

    const result = await executeTool(pi, "PromoteFinding", {
      id,
      poc_path: deadControl,
      control_target: "https://control.example",
      control_path: deadControl,
      local: true,
    });
    expect(result.isError).toBe(true);
    expect(result.details.evidenceFailed).toBe(true);
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

  test("ConfirmFinding requires a pending bundle and a complete verdict", async () => {
    const pi = createFakePi();
    casefileExtension(pi as any);

    const added = await addCase(pi, {
      title: "Confirm without phase 1",
      status: "investigating",
      evidence: "reflected input",
      confidence: "high",
      severity: "medium",
      poc: "send payload, check reflection",
      impact: "script execution",
      target: "example-app",
    });
    const id = added.details.record.id;

    const completeVerdict = {
      verdict: "CONFIRMED",
      reasoning: "re-sent the verify request: effect reproduced on target only",
      evidence_reviewed: ["evidence.json (target run)"],
      re_execution_note: "fresh harness replay matched only the target",
      differential: "target_only",
      disconfirmation_attempt: "tried a patched replica and a second account — no effect",
      canary_assessment: "not_applicable",
      canary_reason: "the fixture response has no attacker-reflected field",
      model: "test-model",
    };

    // No pending bundle (PromoteFinding never ran) → the verdict cannot apply.
    let err: Error | undefined;
    try {
      await executeTool(pi, "ConfirmFinding", { id, verdict: completeVerdict });
    } catch (e) {
      err = e as Error;
    }
    expect(err).toBeDefined();
    expect(err!.message).toContain("No pending confirmation");

    // A CONFIRMED verdict missing the mandatory fields is rejected.
    const phase1 = await executeTool(pi, "PromoteFinding", {
      id,
      poc_path: pocScriptPath,
      control_target: "https://control.example",
      control_path: controlScriptPath,
      local: true,
    });
    expect(phase1.details?.record?.status).toBe("investigating");

    // Workers may gather evidence, but validation and confirmation are main-agent-only.
    process.env.PI_SUBAGENT_CHILD = "1";
    const workerPromote = await executeTool(pi, "PromoteFinding", {
      id,
      poc_path: pocScriptPath,
      control_target: "https://control.example",
      control_path: controlScriptPath,
      local: true,
    });
    expect(workerPromote.isError).toBe(true);
    expect(workerPromote.content?.[0]?.text).toContain("reserved for the main/coordinator agent");

    let workerErr: Error | undefined;
    try {
      await executeTool(pi, "ConfirmFinding", { id, verdict: completeVerdict });
    } catch (e) {
      workerErr = e as Error;
    } finally {
      delete process.env.PI_SUBAGENT_CHILD;
    }
    expect(workerErr).toBeDefined();
    expect(workerErr!.message).toContain("reserved for the main/coordinator agent");
    expect(getCaseById(id)?.status).toBe("investigating");

    let badVerdictErr: Error | undefined;
    try {
      await executeTool(pi, "ConfirmFinding", {
        id,
        verdict: { ...completeVerdict, re_execution_note: undefined },
      });
    } catch (e) {
      badVerdictErr = e as Error;
    }
    expect(badVerdictErr).toBeDefined();
    expect(badVerdictErr!.message).toContain("re_execution_note");

    // Phase 2 is not a caller-supplied checkbox: ConfirmFinding performs a
    // fresh harness replay and fails closed if the control is inconclusive.
    setHarnessFetchForTest(async (input: string | URL) => {
      const url = new URL(String(input));
      if (url.hostname.includes("control")) throw new Error("control unavailable");
      return new Response("root:x:0:0:root:/root:/bin/sh", { status: 200 });
    });
    let replayErr: Error | undefined;
    try {
      await executeTool(pi, "ConfirmFinding", { id, verdict: completeVerdict });
    } catch (e) {
      replayErr = e as Error;
    } finally {
      setHarnessFetchForTest(
        globalThis.fetch as unknown as (input: string | URL) => Promise<Response>,
      );
    }
    expect(replayErr).toBeDefined();
    expect(replayErr!.message).toContain("MAIN-AGENT REPLAY FAILED");
    expect(getCaseById(id)?.status).toBe("investigating");

    // A complete verdict commits.
    const confirmed = await executeTool(pi, "ConfirmFinding", {
      id,
      verdict: completeVerdict,
    });
    expect(confirmed.details.promoted).toBe(true);
    expect(confirmed.details.record.status).toBe("confirmed");
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

  test("PromoteFinding rejects evidence not bound to this run (nonce mismatch)", async () => {
    const pi = createFakePi();
    casefileExtension(pi as any);

    const added = await addCase(pi, {
      title: "Copy-pasted evidence",
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
    });

    // The PoC writes a well-formed evidence.json but with a HARDCODED nonce —
    // copy-pasted evidence from an earlier run must not bind to this one.
    const staleNonce = join(tempDir, "stale-nonce.sh");
    writeFileSync(
      staleNonce,
      [
        "#!/bin/sh",
        'E="$PI_POC_EVIDENCE_DIR"',
        'mkdir -p "$E"',
        'printf \'{"nonce":"stale-nonce","claim":"read /etc/passwd","verify":{"method":"GET","url":"http://%s/read?file=/etc/passwd","expect":{"status":[200],"body_contains":["root:"]}},"observations":["root:"]}\' "$PI_POC_TARGET" > "$E/evidence.json"',
        "exit 0",
        "",
      ].join("\n"),
      "utf8",
    );

    const result = await executeTool(pi, "PromoteFinding", {
      id,
      poc_path: staleNonce,
      control_target: "https://control.example",
      control_path: staleNonce,
      local: true,
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("nonce");
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

  test("XP mode swarm: injects cyber workflow even with an empty ledger", async () => {
    const previous = process.env.PI_XP_MODE;
    process.env.PI_XP_MODE = "swarm";
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

  test("XP mode swarm + subagent child process: before_agent_start injects nothing", async () => {
    const previousXp = process.env.PI_XP_MODE;
    const previousChild = process.env.PI_SUBAGENT_CHILD;
    process.env.PI_XP_MODE = "swarm";
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

  test("XP swarm toggle mid-session re-injects the workflow", async () => {
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

      // /xp swarm → workflow injected.
      await xpCmd.handler("swarm", { ui: { notify } });
      const on1 = await handler({ systemPrompt: "p" });
      expect(on1.systemPrompt).toContain("# Cyber Workflow");

      // /xp off → nothing injected.
      await xpCmd.handler("off", { ui: { notify } });
      expect(await handler({ systemPrompt: "p" })).toBeUndefined();

      // /xp swarm again → workflow must come back (regression: workflowInjected
      // stayed true from the first enable, so re-enabling silently never
      // re-injected the workflow until process restart).
      await xpCmd.handler("swarm", { ui: { notify } });
      const on2 = await handler({ systemPrompt: "p" });
      expect(on2.systemPrompt).toContain("# Cyber Workflow");
    } finally {
      if (previous === undefined) delete process.env.PI_XP_MODE;
      else process.env.PI_XP_MODE = previous;
    }
  });

  test("XP mode swarm: workflow injected once per session, case list refreshes per prompt", async () => {
    const previous = process.env.PI_XP_MODE;
    process.env.PI_XP_MODE = "swarm";
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

  test("XP mode swarm: injects only active cases into before_agent_start context", async () => {
    const previous = process.env.PI_XP_MODE;
    process.env.PI_XP_MODE = "swarm";
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
        control_target: "https://control.example",
        control_path: controlScriptPath,
        local: true,
      });
      await executeTool(pi, "ConfirmFinding", {
        id: reported.details.record.id,
        verdict: {
          verdict: "CONFIRMED",
          reasoning: "re-sent the verify request: effect reproduced on target only",
          evidence_reviewed: ["evidence.json (target run)"],
          re_execution_note: "fresh harness replay matched only the target",
          differential: "target_only",
          disconfirmation_attempt: "tried a patched replica — no effect; target-dependent",
          canary_assessment: "not_applicable",
          canary_reason: "the fixture response has no attacker-reflected field",
          model: "test-model",
        },
      });
      const ctxResult = await executeTool(pi, "CaseContext", { id: reported.details.record.id });
      // The main agent creates the report file (passing the content gate:
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

  test("XP mode swarm: includes hypothesis and blocked cases in prompt context", async () => {
    const previous = process.env.PI_XP_MODE;
    process.env.PI_XP_MODE = "swarm";
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
    process.env.PI_XP_MODE = "swarm";
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
    expect(STATIC_CYBER_WORKFLOW).toContain("only auditor (HUNT rounds), tracer");
    expect(STATIC_CYBER_WORKFLOW).toContain("VALIDATE (you, inline)");
    expect(STATIC_CYBER_WORKFLOW).toContain("REPORT (you, inline)");
    expect(STATIC_CYBER_WORKFLOW).toContain("maximum reachable impact");
    expect(STATIC_CYBER_WORKFLOW).toContain("Do not stop at a benign marker");
    expect(STATIC_CYBER_WORKFLOW).toContain("UNDETERMINED → block/re-dispatch");
    for (const removedAgent of ["report" + "er", "explo" + "it"]) {
      expect(STATIC_CYBER_WORKFLOW).not.toContain(`agent: '${removedAgent}'`);
    }
    expect(STATIC_CYBER_WORKFLOW_LITE).toContain("Report style checklist");
    expect(STATIC_CYBER_WORKFLOW_LITE).toContain("CaseContext");
    expect(STATIC_CYBER_WORKFLOW_LITE).not.toContain("CaseReport");
    for (const workflow of [STATIC_CYBER_WORKFLOW, STATIC_CYBER_WORKFLOW_OMP]) {
      expect(workflow).not.toContain("| CHAIN | INVESTIGATING |");
      expect(workflow).toContain("| MAIN REVIEW | CONFIRMED |");
      expect(workflow).toContain("| CHAIN | CONFIRMED |");
    }
  });

  test("/xp command defaults to swarm and /xp lite keeps single-agent mode", async () => {
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

      await pi.commands.get("xp").handler("", ctx);
      expect(notifications.some((n) => n.includes("SWARM"))).toBe(true);
      const event = { systemPrompt: "" };
      const defaultResult = await handler(event);
      expect(defaultResult.systemPrompt).toContain("# Cyber Workflow");
      expect(defaultResult.systemPrompt).not.toContain("# Cyber Workflow — LITE");

      await pi.commands.get("xp").handler("off", ctx);
      expect(await handler()).toBeUndefined();

      await pi.commands.get("xp").handler("on", ctx);
      expect(notifications.some((n) => n.includes("SWARM"))).toBe(true);
      const onResult = await handler(event);
      expect(onResult.systemPrompt).toContain("# Cyber Workflow");
      expect(onResult.systemPrompt).not.toContain("# Cyber Workflow — LITE");

      await pi.commands.get("xp").handler("off", ctx);
      expect(await handler()).toBeUndefined();

      await pi.commands.get("xp").handler("lite", ctx);
      expect(notifications.some((n) => n.includes("LITE"))).toBe(true);
      const liteResult = await handler(event);
      expect(liteResult.systemPrompt).toContain("# Cyber Workflow — LITE (Single-Agent)");
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
      control_target: "https://control.example",
      control_path: controlScriptPath,
      local: true,
    });
    await executeTool(pi, "ConfirmFinding", {
      id: storedXss.details.record.id,
      verdict: {
        verdict: "CONFIRMED",
        reasoning: "re-sent the verify request: payload rendered on target only",
        evidence_reviewed: ["evidence.json (target run)"],
        re_execution_note: "fresh harness replay matched only the target",
        differential: "target_only",
        disconfirmation_attempt: "rendered a control note without script — no execution",
        canary_assessment: "not_applicable",
        canary_reason: "legacy fixture has no canary placeholder",
        model: "test-model",
      },
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
