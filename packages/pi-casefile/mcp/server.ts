import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

import {
  STATUS_VALUES,
  CONFIDENCE_VALUES,
  SEVERITY_VALUES,
  PRIORITY_VALUES,
  SEARCH_FIELD_VALUES,
  addCaseResult,
  countCases,
  formatCase,
  formatCaseDetail,
  formatCases,
  getCaseById,
  getCasefilePath,
  linkCasesResult,
  promoteFindingResult,
  readCasefile,
  searchCases,
  unlinkCasesResult,
  updateCaseResult,
  writeCaseReport,
} from "../src/ledger.ts";
import { runPoc } from "../src/poc-runner.ts";

type CasefileMcpToolResult = {
  content: [{ type: "text"; text: string }];
  isError?: boolean;
  structuredContent?: Record<string, unknown>;
};

const statusSchema = z.enum(STATUS_VALUES);
const confidenceSchema = z.enum(CONFIDENCE_VALUES);
const severitySchema = z.enum(SEVERITY_VALUES);
const prioritySchema = z.enum(PRIORITY_VALUES);
const searchFieldSchema = z.enum(SEARCH_FIELD_VALUES);

const commonCaseFields = {
  status: statusSchema.optional().describe("Case status"),
  confidence: confidenceSchema.optional().describe("Confidence level"),
  severity: severitySchema.optional().describe("Security severity"),
  priority: prioritySchema.optional().describe("Triage priority"),
  target: z.string().optional().describe("Target asset, host, repo, or scope"),
  endpoint: z.string().optional().describe("Endpoint, route, file, or object"),
  bugClass: z.string().optional().describe("Bug class or root cause category"),
  summary: z.string().optional().describe("Short report summary"),
  evidence: z.string().optional().describe("Observed evidence or repro notes"),
  impact: z.string().optional().describe("Security impact or chain value"),
  nextStep: z.string().optional().describe("Next validation or exploit step"),
  poc: z.string().optional().describe("Proof of concept steps"),
  remediation: z.string().optional().describe("How to fix it"),
  references: z.array(z.string()).optional().describe("External URLs, CVEs, or advisories"),
  blockers: z.array(z.string()).optional().describe("Current blockers"),
  tags: z.array(z.string()).optional().describe("Tags for filtering"),
  assumptions: z.array(z.string()).optional().describe("Explicit assumptions, unknowns, or uncertainty notes"),
};

function textResult(text: string, structuredContent?: Record<string, unknown>): CasefileMcpToolResult {
  return {
    content: [{ type: "text" as const, text }],
    ...(structuredContent === undefined ? {} : { structuredContent }),
  };
}

function errorResult(error: unknown): CasefileMcpToolResult {
  const message = error instanceof Error ? error.message : String(error);
  return {
    isError: true,
    content: [{ type: "text" as const, text: `Casefile error: ${message}` }],
  };
}

async function runTool(
  fn: () => Promise<{ text: string; structuredContent?: Record<string, unknown> }>,
): Promise<CasefileMcpToolResult> {
  try {
    const result = await fn();
    return textResult(result.text, result.structuredContent);
  } catch (error) {
    return errorResult(error);
  }
}

export function createCasefileMcpServer(): McpServer {
  const server = new McpServer({
    name: "casefile",
    version: "1.3.8",
  });

  server.registerTool(
    "casefile_add",
    {
      title: "Add Case",
      description: "Open a new security case as a hypothesis or investigation. Use updates to promote confirmed, blocked, killed, or reported states.",
      inputSchema: {
        title: z.string().describe("Short case title"),
        ...commonCaseFields,
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async (params) => runTool(async () => {
      const result = await addCaseResult(params);
      const text = result.created
        ? `Case opened:\n${formatCaseDetail(result.record)}\n\nLedger: ${getCasefilePath()}`
        : `Case already exists: ${result.reason ?? result.record.id}\n${formatCaseDetail(result.record)}\n\nUse casefile_update only for materially new evidence, PoC, impact, blockers, or status changes.`;
      return { text, structuredContent: { ...result, ledger_path: getCasefilePath() } };
    }),
  );

  server.registerTool(
    "casefile_update",
    {
      title: "Update Case",
      description: "Update an existing case with materially new evidence, status, confidence, blockers, impact, remediation, or next steps.",
      inputSchema: {
        id: z.string().describe("Case ID to update"),
        title: z.string().optional().describe("Updated case title"),
        ...commonCaseFields,
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async (params) => runTool(async () => {
      const { id, ...update } = params;
      const result = await updateCaseResult(id, update);
      const text = result.changed
        ? `Case updated:\n${formatCaseDetail(result.record)}`
        : `Case unchanged: ${result.reason ?? "no material fields changed"}\n${formatCaseDetail(result.record)}`;
      return { text, structuredContent: result };
    }),
  );

  server.registerTool(
    "casefile_promote",
    {
      title: "Promote Finding",
      description: "Run an on-disk PoC script (Docker sandbox or local) and, on exit 0, promote an investigating case to confirmed.",
      inputSchema: {
        id: z.string().describe("Case ID to promote"),
        poc_path: z.string().describe("Absolute path to the PoC script on disk"),
        local: z.boolean().optional().describe("Run locally instead of in Docker sandbox"),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false,
      },
    },
    async (params) => runTool(async () => {
      const run = runPoc(params.poc_path, params.local !== true);
      const result = await promoteFindingResult(params.id, {
        path: run.path,
        exitCode: run.exitCode,
        ranAt: run.ranAt,
        output: run.output,
        sandbox: run.sandbox,
      });
      const text = run.exitCode === 0
        ? `PoC verified (exit ${run.exitCode}). Case promoted to confirmed:\n${formatCaseDetail(result.record)}`
        : `PoC failed (exit ${run.exitCode}). Case remains investigating.\nOutput:\n${run.output}`;
      return { text, structuredContent: { ...result, run } };
    }),
  );

  server.registerTool(
    "casefile_get",
    {
      title: "Get Case",
      description: "Get full details of a single case by ID.",
      inputSchema: {
        id: z.string().describe("Case ID"),
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async ({ id }) => runTool(async () => {
      const record = getCaseById(id);
      if (!record) throw new Error(`Case not found: ${id}`);
      return { text: formatCaseDetail(record), structuredContent: { record } };
    }),
  );

  server.registerTool(
    "casefile_list",
    {
      title: "List Cases",
      description: "List cases with optional status, confidence, severity, priority, tag, and pagination filters.",
      inputSchema: {
        status: statusSchema.optional(),
        confidence: confidenceSchema.optional(),
        severity: severitySchema.optional(),
        priority: prioritySchema.optional(),
        tag: z.string().optional().describe("Filter by tag"),
        limit: z.number().int().min(1).max(200).optional().describe("Max results, default 50"),
        offset: z.number().int().min(0).optional().describe("Skip N results for pagination"),
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async (params) => runTool(async () => {
      const result = await searchCases(params);
      const offset = params.offset ?? 0;
      const header = `Showing ${result.cases.length} of ${result.total} cases (offset: ${offset})`;
      const body = result.cases.length > 0 ? formatCases(result.cases) : "No cases match filters.";
      return { text: `${header}\n${body}`, structuredContent: { ...result, offset } };
    }),
  );

  server.registerTool(
    "casefile_search",
    {
      title: "Search Cases",
      description: "Full-text search across cases, optionally restricted to title, summary, evidence, impact, target, endpoint, bugClass, or poc.",
      inputSchema: {
        query: z.string().describe("Text to search across cases"),
        field: searchFieldSchema.optional().describe("Restrict search to a specific field"),
        status: statusSchema.optional(),
        confidence: confidenceSchema.optional(),
        severity: severitySchema.optional(),
        priority: prioritySchema.optional(),
        tag: z.string().optional(),
        limit: z.number().int().min(1).max(200).optional(),
        offset: z.number().int().min(0).optional(),
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async (params) => runTool(async () => {
      const result = await searchCases(params);
      const offset = params.offset ?? 0;
      const header = `Search "${params.query}"${params.field ? ` in ${params.field}` : ""}: ${result.cases.length} of ${result.total} results (offset: ${offset})`;
      const body = result.cases.length > 0 ? formatCases(result.cases) : "No matching cases.";
      return { text: `${header}\n${body}`, structuredContent: { ...result, offset } };
    }),
  );

  server.registerTool(
    "casefile_link",
    {
      title: "Link Cases",
      description: "Bidirectionally link two cases into an exploit chain or related investigation trail.",
      inputSchema: {
        source_id: z.string().describe("First case ID"),
        target_id: z.string().describe("Second case ID"),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async ({ source_id, target_id }) => runTool(async () => {
      const result = await linkCasesResult(source_id, target_id);
      const text = result.changed
        ? `Linked:\n  ${formatCase(result.source)}\n  <->\n  ${formatCase(result.target)}`
        : `Link unchanged: ${result.reason ?? "no material change"}\n  ${formatCase(result.source)}\n  <->\n  ${formatCase(result.target)}`;
      return { text, structuredContent: result };
    }),
  );

  server.registerTool(
    "casefile_unlink",
    {
      title: "Unlink Cases",
      description: "Remove a bidirectional link between two cases.",
      inputSchema: {
        source_id: z.string().describe("First case ID"),
        target_id: z.string().describe("Second case ID"),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async ({ source_id, target_id }) => runTool(async () => {
      const result = await unlinkCasesResult(source_id, target_id);
      const text = result.changed
        ? `Unlinked:\n  ${formatCase(result.source)}\n  -/->\n  ${formatCase(result.target)}`
        : `Unlink unchanged: ${result.reason ?? "no material change"}\n  ${formatCase(result.source)}\n  -/->\n  ${formatCase(result.target)}`;
      return { text, structuredContent: result };
    }),
  );

  server.registerTool(
    "casefile_report",
    {
      title: "Write Case Report",
      description: "Generate a markdown report from a confirmed or reported case under the casefile report directory.",
      inputSchema: {
        id: z.string().describe("Case ID to turn into a markdown report"),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async ({ id }) => runTool(async () => {
      const result = await writeCaseReport(id);
      return {
        text: `Report written: ${result.path}\n${formatCase(result.record)}`,
        structuredContent: result,
      };
    }),
  );

  server.registerTool(
    "casefile_count",
    {
      title: "Count Cases",
      description: "Return total case count grouped by status and severity.",
      inputSchema: {},
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async () => runTool(async () => {
      const result = await countCases();
      return {
        text: `Casefile: ${result.total} total | Status: ${Object.entries(result.byStatus).map(([key, value]) => `${key}:${value}`).join(", ")} | Severity: ${Object.entries(result.bySeverity).map(([key, value]) => `${key}:${value}`).join(", ")}`,
        structuredContent: result,
      };
    }),
  );

  return server;
}

export async function startCasefileMcpServer(): Promise<void> {
  const server = createCasefileMcpServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

if (import.meta.main) {
  startCasefileMcpServer().catch((error) => {
    console.error("Casefile MCP server failed:", error);
    process.exit(1);
  });
}
