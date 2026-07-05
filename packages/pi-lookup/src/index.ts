/**
 * pi-lookup — web search, page fetch, library docs, and repo Q&A.
 *
 * Tools: web_search, web_fetch, context7, deepwiki
 */

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Text } from "@earendil-works/pi-tui";
import websearchExtension from "./websearch.ts";
import { context7Tool } from "./context7.ts";
import { deepwikiTool } from "./deepwiki.ts";

export default function piLookup(pi: ExtensionAPI) {
  // Register web_search + web_fetch
  websearchExtension(pi);

  // ── context7 ──

  pi.registerTool({
    name: context7Tool.name,
    label: context7Tool.label,
    description: context7Tool.description,
    parameters: context7Tool.parameters,

    async execute(_id, params, signal, _onUpdate, _ctx) {
      try {
        const result = await context7Tool.execute(_id, params as Record<string, unknown>, signal);
        return result;
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: `Context7 error: ${(error as Error).message}` }],
          isError: true,
          details: {},
        };
      }
    },

    renderCall(args, theme) {
      return new Text(
        theme.fg("toolTitle", theme.bold("Context7 ")) + theme.fg("dim", (args.libraryName as string) ?? ""),
        0,
        0,
      );
    },

    renderResult(result, _options, theme) {
      if ((result as { isError?: boolean }).isError) {
        return new Text(theme.fg("error", "✗ Context7 failed"), 0, 0);
      }
      const details = result.details as { libraryId?: string } | undefined;
      return new Text(theme.fg("success", "✓ Docs ") + theme.fg("muted", details?.libraryId ?? ""), 0, 0);
    },
  });

  // ── deepwiki ──

  pi.registerTool({
    name: deepwikiTool.name,
    label: deepwikiTool.label,
    description: deepwikiTool.description,
    parameters: deepwikiTool.parameters,

    async execute(_id, params, signal, _onUpdate, _ctx) {
      try {
        const result = await deepwikiTool.execute(_id, params as Record<string, unknown>, signal);
        return result;
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: `DeepWiki error: ${(error as Error).message}` }],
          isError: true,
          details: {},
        };
      }
    },

    renderCall(args, theme) {
      return new Text(
        theme.fg("toolTitle", theme.bold("DeepWiki ")) + theme.fg("dim", (args.repo as string) ?? ""),
        0,
        0,
      );
    },

    renderResult(result, _options, theme) {
      if ((result as { isError?: boolean }).isError) {
        return new Text(theme.fg("error", "✗ DeepWiki failed"), 0, 0);
      }
      const details = result.details as { repo?: string } | undefined;
      return new Text(theme.fg("success", "✓ Answer ") + theme.fg("muted", details?.repo ?? ""), 0, 0);
    },
  });
}
