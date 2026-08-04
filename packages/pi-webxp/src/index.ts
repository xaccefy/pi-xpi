/**
 * pi-webxp — web search, page fetch, library docs, repo Q&A, and exploit technique search.
 *
 * Tools: web_search, web_fetch, context7, deepwiki, exploit_search, http_request
 *
 * Merges the former pi-lookup and pi-exploitsearch extensions into one
 * "find information" surface: general web lookups, library docs, repo Q&A,
 * and the preview.is offense-specific technique corpus.
 */

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Text } from "@earendil-works/pi-tui";
import { context7Tool } from "./context7.ts";
import { deepwikiTool } from "./deepwiki.ts";
import exploitSearchExtension from "./exploitsearch.ts";
import httpRequestExtension from "./httprequest.ts";
import websearchExtension from "./websearch.ts";

export default function piWebxp(pi: ExtensionAPI) {
  // web_search + web_fetch
  websearchExtension(pi);

  // exploit_search (preview.is corpus)
  exploitSearchExtension(pi);

  // ── http_request ──
  httpRequestExtension(pi);

  // ── context7 + deepwiki (same registration shape: name, call arg, success noun) ──

  for (const [tool, callArg, resultKey, noun] of [
    [context7Tool, "libraryName", "libraryId", "Docs"],
    [deepwikiTool, "repo", "repo", "Answer"],
  ] as const) {
    pi.registerTool({
      name: tool.name,
      label: tool.label,
      description: tool.description,
      promptSnippet: tool.promptSnippet,
      promptGuidelines: tool.promptGuidelines,
      parameters: tool.parameters,

      async execute(_id, params, signal, _onUpdate, _ctx) {
        try {
          return await tool.execute(_id, params as Record<string, unknown>, signal);
        } catch (error) {
          return {
            content: [
              { type: "text" as const, text: `${tool.label} error: ${(error as Error).message}` },
            ],
            isError: true,
            details: {},
          };
        }
      },

      renderCall(args, theme) {
        return new Text(
          theme.fg("toolTitle", theme.bold(`${tool.label} `)) +
            theme.fg("dim", ((args as Record<string, unknown>)[callArg] as string) ?? ""),
          0,
          0,
        );
      },

      renderResult(result, _options, theme) {
        if ((result as { isError?: boolean }).isError) {
          return new Text(theme.fg("error", `✗ ${tool.label} failed`), 0, 0);
        }
        const details = result.details as Record<string, string> | undefined;
        return new Text(
          theme.fg("success", `✓ ${noun} `) + theme.fg("muted", details?.[resultKey] ?? ""),
          0,
          0,
        );
      },
    });
  }
}
