import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { context7Tool } from "../src/context7.ts";
import { deepwikiTool } from "../src/deepwiki.ts";

const originalFetch = globalThis.fetch;

describe("pi-lookup context7", () => {
  beforeEach(() => {
    globalThis.fetch = (async (url: string | URL | Request, _init?: RequestInit) => {
      const urlStr = url.toString();

      if (urlStr.includes("/search")) {
        if (urlStr.includes("unknownlib")) {
          return { ok: true, json: async () => ({ results: [] }) } as Response;
        }
        return { ok: true, json: async () => ({ results: [{ id: "lib123" }] }) } as Response;
      }

      if (urlStr.includes("/lib123")) {
        return {
          ok: true,
          headers: new Headers({ "content-type": "application/json" }),
          text: async () =>
            JSON.stringify({
              content: "Mocked library documentation",
              metadata: { title: "React Docs", url: "https://react.dev" },
            }),
        } as Response;
      }

      return { ok: false, status: 404 } as Response;
    }) as any;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("fetches documentation successfully", async () => {
    const result = await context7Tool.execute("call1", { libraryName: "react" });
    expect(result.details.provider).toBe("context7");
    expect(result.details.libraryId).toBe("lib123");
    expect(result.content[0].text).toContain("Mocked library documentation");
    expect(result.content[0].text).toContain("React Docs");
  });

  it("handles unknown libraries", async () => {
    await expect(context7Tool.execute("call1", { libraryName: "unknownlib" })).rejects.toThrow(
      /Library not found on Context7/,
    );
  });
});

describe("pi-lookup deepwiki", () => {
  beforeEach(() => {
    globalThis.fetch = (async (_url: string | URL | Request, _init?: RequestInit) => {
      return {
        ok: true,
        text: async () =>
          JSON.stringify({
            jsonrpc: "2.0",
            result: {
              content: [{ type: "text", text: "Here is the answer about facebook/react." }],
            },
          }),
      } as Response;
    }) as any;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("queries DeepWiki MCP server successfully", async () => {
    const result = await deepwikiTool.execute("call1", {
      repo: "facebook/react",
      question: "How does it work?",
    });
    expect(result.details.provider).toBe("deepwiki");
    expect(result.details.repo).toBe("facebook/react");
    expect(result.content[0].text).toBe("Here is the answer about facebook/react.");
  });
});
