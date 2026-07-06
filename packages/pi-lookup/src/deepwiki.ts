/**
 * deepwiki — ask questions about any public GitHub repository.
 *
 * Uses DeepWiki MCP server (https://mcp.deepwiki.com/mcp) via JSON-RPC.
 * No API key required.
 */

import { Type } from "@sinclair/typebox";

const DEEPWIKI_MCP_URL = "https://mcp.deepwiki.com/mcp";
const DEEPWIKI_TOOL = "ask_question";
const DEFAULT_TIMEOUT_MS = 30_000;

type McpContentItem = { type: string; text?: string };

export const deepwikiTool = {
  name: "deepwiki",
  label: "DeepWiki",
  description:
    "Ask questions about any public GitHub repository. " +
    "Use repo='owner/name' (e.g. 'facebook/react') and a natural-language question. " +
    "Returns synthesized answer with citations to source files.",
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

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT_MS);
    if (signal) {
      if (signal.aborted) controller.abort(signal.reason);
      else signal.addEventListener("abort", () => controller.abort(signal.reason), { once: true });
    }

    try {
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
        signal: controller.signal,
      });

      if (!response.ok) {
        throw new Error(`DeepWiki returned ${response.status}: ${response.statusText}`);
      }

      const text = await response.text();
      const textParts: string[] = [];

      // Try to parse as JSON-RPC response
      try {
        const msg = JSON.parse(text);
        if (msg.result?.content && Array.isArray(msg.result.content)) {
          for (const item of msg.result.content as McpContentItem[]) {
            if (item.type === "text" && item.text) textParts.push(item.text);
          }
        } else if (msg.error?.message) {
          throw new Error(`DeepWiki error: ${msg.error.message}`);
        }
      } catch (parseErr) {
        // Fallback: server returned plain text
        if (parseErr instanceof SyntaxError) {
          textParts.push(text.slice(0, 5000));
        } else {
          throw parseErr;
        }
      }

      return {
        content: [{ type: "text" as const, text: textParts.join("\n") || text.slice(0, 5000) }],
        details: { provider: "deepwiki", repo, question },
      };
    } catch (error) {
      if (controller.signal.aborted) {
        // Distinguish between our internal timeout and a parent-signal abort
        const reason = signal?.aborted
          ? "DeepWiki aborted by caller"
          : `DeepWiki timed out after ${DEFAULT_TIMEOUT_MS}ms`;
        throw new Error(reason);
      }
      throw new Error(`DeepWiki failed: ${(error as Error).message}`);
    } finally {
      clearTimeout(timer);
    }
  },
};
