/**
 * context7 — fetch up-to-date library documentation.
 *
 * Uses https://context7.com/api — no API key required.
 * Step 1: resolve library name to ID via /search
 * Step 2: fetch docs via /{id}?type=txt&tokens=...&topic=...
 */

import { Type } from "@sinclair/typebox";

const CONTEXT7_API = "https://context7.com/api";

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
    const maxTokens = (params.maxTokens as number | undefined) ?? 10000;

    if (!libraryName) throw new Error("libraryName is required.");

    const requestSignal = AbortSignal.any([
      ...(signal ? [signal] : []),
      AbortSignal.timeout(30000),
    ]);

    // Step 1: resolve library name to ID
    const searchUrl = `${CONTEXT7_API}/search?query=${encodeURIComponent(libraryName)}`;
    const searchRes = await fetch(searchUrl, { signal: requestSignal });
    if (!searchRes.ok) throw new Error(`Context7 search failed: ${searchRes.status}`);

    const searchData = (await searchRes.json()) as Context7SearchResponse;
    if (!searchData.results?.length) {
      throw new Error(`Library not found on Context7: ${libraryName}`);
    }
    const libraryId = searchData.results[0].id;

    // Step 2: fetch docs
    const docParams = new URLSearchParams();
    docParams.set("type", "txt");
    docParams.set("tokens", String(maxTokens));
    if (topic) docParams.set("topic", topic);

    const docsUrl = `${CONTEXT7_API}/${libraryId}?${docParams.toString()}`;
    const docsRes = await fetch(docsUrl, { signal: requestSignal });
    if (!docsRes.ok) throw new Error(`Context7 docs failed: ${docsRes.status}`);

    const body = await docsRes.text();
    const contentType = docsRes.headers.get("content-type") ?? "";
    let docs: Context7DocsResponse;

    if (contentType.includes("application/json") || body.trimStart().startsWith("{")) {
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

    return {
      content: [{ type: "text" as const, text: lines.join("\n").trim() }],
      details: { provider: "context7", libraryId, topic, contentLength: docs.content?.length ?? 0 },
    };
  },
};
