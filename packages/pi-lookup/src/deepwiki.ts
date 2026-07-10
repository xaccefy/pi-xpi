/**
 * deepwiki — ask questions about any public GitHub repository.
 *
 * Uses DeepWiki MCP server (https://mcp.deepwiki.com/mcp) via JSON-RPC.
 * No API key required.
 */

import { Type } from "@sinclair/typebox";
import { TtlLruCache } from "./cache.ts";

const DEEPWIKI_MCP_URL = "https://mcp.deepwiki.com/mcp";
const DEEPWIKI_TOOL = "ask_question";
const DEFAULT_TIMEOUT_MS = 30_000;
const DEEPWIKI_CACHE_TTL_MS = 10 * 60 * 1000;
const deepwikiCache = new TtlLruCache<string>(DEEPWIKI_CACHE_TTL_MS, 64);

type McpContentItem = { type: string; text?: string };

type McpJsonRpc = {
  result?: { content?: McpContentItem[]; isError?: boolean };
  error?: { message?: string };
};

/** Parse a single JSON-RPC MCP tools/call response into joined text content. */
function textFromMcpMessage(msg: McpJsonRpc): string {
  if (msg.error?.message) {
    throw new Error(`DeepWiki error: ${msg.error.message}`);
  }
  if (msg.result?.isError) {
    const errText = (msg.result.content ?? [])
      .filter((i) => i.type === "text" && i.text)
      .map((i) => i.text)
      .join("\n");
    throw new Error(errText || "DeepWiki tool returned isError=true");
  }
  const parts = (msg.result?.content ?? [])
    .filter((i) => i.type === "text" && i.text)
    .map((i) => i.text as string);
  if (parts.length === 0) {
    throw new Error("DeepWiki returned empty content");
  }
  return parts.join("\n");
}

/**
 * MCP Streamable HTTP may return application/json OR text/event-stream.
 * Never treat raw protocol text as a successful answer (that poisons the cache).
 */
function extractDeepwikiText(body: string, contentType: string): string {
  const looksLikeSse =
    contentType.includes("text/event-stream") ||
    /^\s*event:/m.test(body) ||
    /^\s*data:/m.test(body);

  if (looksLikeSse) {
    let last: McpJsonRpc | undefined;
    for (const line of body.split(/\r?\n/)) {
      if (!line.startsWith("data:")) continue;
      const payload = line.slice(5).trim();
      if (!payload || payload === "[DONE]") continue;
      try {
        last = JSON.parse(payload) as McpJsonRpc;
      } catch {
        // skip non-JSON data frames
      }
    }
    if (!last) {
      throw new Error("DeepWiki returned SSE without a parseable JSON-RPC payload");
    }
    return textFromMcpMessage(last);
  }

  let msg: McpJsonRpc;
  try {
    msg = JSON.parse(body) as McpJsonRpc;
  } catch {
    throw new Error("DeepWiki returned a non-JSON response");
  }
  return textFromMcpMessage(msg);
}

export const deepwikiTool = {
  name: "deepwiki",
  label: "DeepWiki",
  description:
    "Ask questions about any public GitHub repository. " +
    "Use repo='owner/name' (e.g. 'facebook/react') and a natural-language question. " +
    "Returns synthesized answer with citations to source files.",
  promptSnippet: "Ask questions about a public GitHub repo",
  promptGuidelines: [
    "Use deepwiki to understand a public GitHub repository: architecture, how a feature works, or how to use it, by asking natural-language questions about owner/name.",
    "Prefer deepwiki over web_search/web_fetch when the target is a public repo and the user wants a synthesized, cited answer rather than raw files.",
  ],
  parameters: Type.Object(
    {
      repo: Type.String({
        description: "GitHub repo in 'owner/name' format, e.g. 'facebook/react'",
        pattern: "^[\\w.-]+/[\\w.-]+$",
      }),
      question: Type.String({ description: "Natural-language question about the repository" }),
    },
    { additionalProperties: false },
  ),

  async execute(_id: string, params: Record<string, unknown>, signal?: AbortSignal) {
    const repo = (params.repo as string | undefined)?.trim();
    const question = (params.question as string | undefined)?.trim();

    if (!repo) throw new Error("repo is required (e.g. 'facebook/react').");
    if (!question) throw new Error("question is required.");

    const cacheKey = `${repo}|${question}`;

    try {
      const finalText = await deepwikiCache.getOrLoad(cacheKey, async () => {
        const requestSignal = AbortSignal.any([
          ...(signal ? [signal] : []),
          AbortSignal.timeout(DEFAULT_TIMEOUT_MS),
        ]);

        const body = JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: { name: DEEPWIKI_TOOL, arguments: { repo, question } },
        });

        const response = await fetch(DEEPWIKI_MCP_URL, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Accept: "application/json, text/event-stream",
          },
          body,
          signal: requestSignal,
        });

        if (!response.ok) {
          throw new Error(`DeepWiki returned ${response.status}: ${response.statusText}`);
        }

        const text = await response.text();
        const contentType =
          (typeof response.headers?.get === "function"
            ? response.headers.get("content-type")
            : undefined) ?? "";
        return extractDeepwikiText(text, contentType);
      });

      return {
        content: [{ type: "text" as const, text: finalText }],
        details: { provider: "deepwiki", repo, question },
      };
    } catch (error) {
      const msg = (error as Error).message ?? String(error);
      if (signal?.aborted) throw new Error("DeepWiki aborted by caller");
      if (/aborted|timeout|TimeoutError/i.test(msg) || msg.includes("The operation was aborted")) {
        throw new Error(`DeepWiki timed out after ${DEFAULT_TIMEOUT_MS}ms`);
      }
      throw new Error(`DeepWiki failed: ${msg}`);
    }
  },
};
