import { afterEach, beforeEach, describe, expect, mock, test } from "bun:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { mkdtemp, rm } from "fs/promises";
import { join } from "path";
import { tmpdir } from "os";

import { createCasefileMcpServer } from "../mcp/server.ts";
import { readCasefile, setCasefilePath } from "../src/ledger.ts";

mock.module("../src/poc-runner.ts", () => ({
  runPoc: () => ({ path: "/mock/poc.sh", exitCode: 0, output: "ok", ranAt: "2024-01-01T00:00:00Z", sandbox: true }),
}));

let tempDir: string;

async function connectCasefileMcp() {
  const server = createCasefileMcpServer();
  const client = new Client({
    name: "casefile-test-client",
    version: "1.0.0",
  });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  return { client, server };
}

beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), "casefile-mcp-test-"));
  setCasefilePath(join(tempDir, "casefile.db"));
});

afterEach(async () => {
  setCasefilePath(undefined);
  await rm(tempDir, { recursive: true, force: true });
});

describe("casefile MCP server", () => {
  test("registers casefile tools and uses the shared ledger", async () => {
    const { client, server } = await connectCasefileMcp();
    try {
      const tools = await client.listTools();
      expect(tools.tools.map((tool) => tool.name).sort()).toEqual([
        "casefile_add",
        "casefile_count",
        "casefile_get",
        "casefile_link",
        "casefile_list",
        "casefile_promote",
        "casefile_report",
        "casefile_search",
        "casefile_unlink",
        "casefile_update",
      ]);

      const added = await client.callTool({
        name: "casefile_add",
        arguments: {
          title: "Codex SSRF candidate",
          status: "investigating",
          confidence: "medium",
          target: "api.example.test",
          evidence: "Backend fetches user-provided URLs",
          tags: ["ssrf"],
        },
      });
      const created = added.structuredContent as any;
      expect(created.created).toBe(true);
      expect(created.record.title).toBe("Codex SSRF candidate");

      const updated = await client.callTool({
        name: "casefile_update",
        arguments: {
          id: created.record.id,
          confidence: "high",
          severity: "high",
          poc: "Request the fetch endpoint with a collaborator URL and observe the callback",
          impact: "Server-side request forgery to internal services",
          evidence: "Backend fetches user-provided URLs",
        },
      });
      expect((updated.structuredContent as any).record.status).toBe("investigating");

      const promoted = await client.callTool({
        name: "casefile_promote",
        arguments: {
          id: created.record.id,
          poc_path: "/mock/poc.sh",
        },
      });
      expect((promoted.structuredContent as any).record.status).toBe("confirmed");

      const searched = await client.callTool({
        name: "casefile_search",
        arguments: {
          query: "collaborator",
          field: "poc",
        },
      });
      expect((searched.structuredContent as any).total).toBe(1);

      const listed = await client.callTool({
        name: "casefile_list",
        arguments: {
          status: "confirmed",
          tag: "ssrf",
        },
      });
      expect((listed.structuredContent as any).total).toBe(1);

      const records = readCasefile();
      expect(records).toHaveLength(1);
      expect(records[0].id).toBe(created.record.id);
    } finally {
      await client.close();
      await server.close();
    }
  });
});
