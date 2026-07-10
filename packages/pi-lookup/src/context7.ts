/**
 * context7 — fetch up-to-date library documentation.
 *
 * Uses https://context7.com/api — no API key required.
 * Step 1: resolve library name to ID via /search
 * Step 2: fetch docs via /{id}?type=txt&tokens=...&topic=...
 */

import { Type } from "@sinclair/typebox";
import { TtlLruCache } from "./cache.ts";

const CONTEXT7_API = "https://context7.com/api";
const STEP_TIMEOUT_MS = 20_000;
const CONTEXT7_CACHE_TTL_MS = 10 * 60 * 1000;
const context7Cache = new TtlLruCache<{ content: string; libraryId: string }>(
  CONTEXT7_CACHE_TTL_MS,
  64,
);

type Context7SearchResponse = {
  results?: Array<{ id: string; name?: string }>;
};

type Context7DocsResponse = {
  content?: string;
  metadata?: { title?: string; url?: string };
};

export const context7Tool = {
  name: "context7",
  label: "Context7 Docs",
  description:
    "Fetch up-to-date documentation for a library. " +
    "Use libraryName (e.g. 'react') and optional topic (e.g. 'hooks'). " +
    "Returns current docs with code examples.",
  promptSnippet: "Fetch current library documentation (with examples)",
  promptGuidelines: [
    "Use context7 when the user asks how to use a library/framework (e.g. 'react', 'zod'), or you need up-to-date API docs and code examples for a dependency.",
    "Prefer context7 over web_search for library how-to questions; scope with topic (e.g. 'hooks', 'validation') when useful.",
  ],
  parameters: Type.Object(
    {
      libraryName: Type.String({ description: "Library name, e.g. 'react', 'next.js', 'zod'" }),
      topic: Type.Optional(
        Type.String({
          description: "Specific topic within the library, e.g. 'hooks', 'routing', 'validation'",
        }),
      ),
      maxTokens: Type.Optional(
        Type.Number({ description: "Max tokens of documentation to return (default 10000)" }),
      ),
    },
    { additionalProperties: false },
  ),

  async execute(_id: string, params: Record<string, unknown>, signal?: AbortSignal) {
    const libraryName = (params.libraryName as string | undefined)?.trim();
    const topic = (params.topic as string | undefined)?.trim();
    const rawMax = (params.maxTokens as number | undefined) ?? 10000;
    const maxTokens = Number.isFinite(rawMax)
      ? Math.max(100, Math.min(Math.trunc(rawMax), 100_000))
      : 10000;

    if (!libraryName) throw new Error("libraryName is required.");

    const cacheKey = `${libraryName}|${topic ?? ""}|${maxTokens}`;

    const { content, libraryId } = await context7Cache.getOrLoad(cacheKey, async () => {
      // Independent per-step budgets so a slow search doesn't starve docs.
      const searchSignal = AbortSignal.any([
        ...(signal ? [signal] : []),
        AbortSignal.timeout(STEP_TIMEOUT_MS),
      ]);

      const searchUrl = `${CONTEXT7_API}/search?query=${encodeURIComponent(libraryName)}`;
      const searchRes = await fetch(searchUrl, { signal: searchSignal });
      if (!searchRes.ok) throw new Error(`Context7 search failed: ${searchRes.status}`);

      const searchData = (await searchRes.json()) as Context7SearchResponse;
      if (!searchData.results?.length) {
        throw new Error(`Library not found on Context7: ${libraryName}`);
      }
      const rawId = searchData.results[0].id;
      if (!rawId) {
        throw new Error(`Context7 returned a result without an id for: ${libraryName}`);
      }
      const libraryId = rawId
        .split("/")
        .filter((seg) => seg.length > 0)
        .map((seg) => encodeURIComponent(seg))
        .join("/");

      const docsSignal = AbortSignal.any([
        ...(signal ? [signal] : []),
        AbortSignal.timeout(STEP_TIMEOUT_MS),
      ]);
      const docParams = new URLSearchParams();
      docParams.set("type", "txt");
      docParams.set("tokens", String(maxTokens));
      if (topic) docParams.set("topic", topic);

      const docsUrl = `${CONTEXT7_API}/${libraryId}?${docParams.toString()}`;
      const docsRes = await fetch(docsUrl, { signal: docsSignal });
      if (!docsRes.ok) throw new Error(`Context7 docs failed: ${docsRes.status}`);

      const body = await docsRes.text();
      const contentType = docsRes.headers.get("content-type") ?? "";
      let docs: Context7DocsResponse;

      // Prefer Content-Type; only treat as JSON when the type says so.
      if (contentType.includes("application/json")) {
        try {
          docs = JSON.parse(body) as Context7DocsResponse;
        } catch {
          docs = { content: body };
        }
      } else {
        docs = { content: body };
      }

      const lines: string[] = [`## ${docs.metadata?.title ?? libraryName}`, ""];
      lines.push(docs.content || "(no content returned)");
      if (docs.metadata?.url) lines.push("", `Source: ${docs.metadata.url}`);

      return { content: lines.join("\n").trim(), libraryId };
    });

    return {
      content: [{ type: "text" as const, text: content }],
      details: { provider: "context7", libraryId, topic, contentLength: content.length },
    };
  },
};
