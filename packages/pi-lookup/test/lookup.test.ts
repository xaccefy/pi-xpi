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

  it("caches identical lookups so only one network round-trip occurs", async () => {
    let calls = 0;
    globalThis.fetch = (async (url: string | URL | Request, _init?: RequestInit) => {
      calls++;
      const urlStr = url.toString();
      if (urlStr.includes("/search")) {
        return { ok: true, json: async () => ({ results: [{ id: "lib-vue" }] }) } as Response;
      }
      if (urlStr.includes("/lib-vue")) {
        return {
          ok: true,
          headers: new Headers({ "content-type": "application/json" }),
          text: async () =>
            JSON.stringify({
              content: "Vue docs",
              metadata: { title: "Vue Docs", url: "https://vuejs.org" },
            }),
        } as Response;
      }
      return { ok: false, status: 404 } as Response;
    }) as any;

    const r1 = await context7Tool.execute("c1", { libraryName: "vue" });
    const r2 = await context7Tool.execute("c2", { libraryName: "vue" });
    expect(r1.details.libraryId).toBe("lib-vue");
    expect(r2.details.libraryId).toBe("lib-vue");
    // search + docs on first call, then a cache hit with zero extra fetches.
    expect(calls).toBe(2);
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

  it("caches identical questions so only one network round-trip occurs", async () => {
    let calls = 0;
    globalThis.fetch = (async (_url: string | URL | Request, _init?: RequestInit) => {
      calls++;
      return {
        ok: true,
        text: async () =>
          JSON.stringify({
            jsonrpc: "2.0",
            result: { content: [{ type: "text", text: "Vue answer" }] },
          }),
      } as Response;
    }) as any;

    const r1 = await deepwikiTool.execute("c1", { repo: "vuejs/core", question: "how?" });
    const r2 = await deepwikiTool.execute("c2", { repo: "vuejs/core", question: "how?" });
    expect(r1.content[0].text).toBe("Vue answer");
    expect(r2.content[0].text).toBe("Vue answer");
    expect(calls).toBe(1);
  });

  it("sends repoName (not repo) as the MCP tool argument", async () => {
    let capturedBody: any;
    globalThis.fetch = (async (_url: string | URL | Request, init?: RequestInit) => {
      capturedBody = JSON.parse(init?.body as string);
      return {
        ok: true,
        text: async () =>
          JSON.stringify({
            jsonrpc: "2.0",
            result: { content: [{ type: "text", text: "ok" }] },
          }),
      } as Response;
    }) as any;

    await deepwikiTool.execute("call1", { repo: "facebook/react", question: "wire format?" });

    expect(capturedBody.method).toBe("tools/call");
    expect(capturedBody.params.name).toBe("ask_question");
    expect(capturedBody.params.arguments.repoName).toBe("facebook/react");
    expect(capturedBody.params.arguments.question).toBe("wire format?");
    expect(capturedBody.params.arguments).not.toHaveProperty("repo");
  });

  it("surfaces DeepWiki schema validation errors from isError envelopes", async () => {
    globalThis.fetch = (async (_url: string | URL | Request, _init?: RequestInit) => {
      return {
        ok: true,
        text: async () =>
          JSON.stringify({
            jsonrpc: "2.0",
            result: {
              content: [
                {
                  type: "text",
                  text: "1 validation error for call[ask_question]\nrepoName\n  Missing required argument",
                },
              ],
              isError: true,
            },
          }),
      } as Response;
    }) as any;

    await expect(
      deepwikiTool.execute("call1", { repo: "facebook/react", question: "boom?" }),
    ).rejects.toThrow(/validation error for call\[ask_question\]/);
  });
});
