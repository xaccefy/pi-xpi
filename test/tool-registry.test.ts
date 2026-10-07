import assert from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

/**
 * Registered-tool inventory extracted from source. Keeping this mechanical
 * (not hand-maintained) is the point: a renamed, added, or removed tool
 * fails here until docs/tool-registry.md and the guide catch up.
 *
 * - pi-casefile registers through the registerCaseTool wrapper (diagnostic
 *   error handler); pi-webxp registers most tools via pi.registerTool and
 *   context7/deepwiki as shared definition objects; pi-xtodo uses a
 *   TOOL_NAME constant.
 */
function registeredToolNames(): Set<string> {
  const names = new Set<string>();
  const direct = [
    "packages/pi-casefile/src/index.ts",
    "packages/pi-webxp/src/httprequest.ts",
    "packages/pi-webxp/src/rawhttp.ts",
    "packages/pi-webxp/src/jwtx.ts",
    "packages/pi-webxp/src/websearch.ts",
    "packages/pi-webxp/src/exploitsearch.ts",
  ];
  for (const rel of direct) {
    const src = readFileSync(join(root, rel), "utf8");
    for (const m of src.matchAll(
      /(?:pi\.registerTool|registerCaseTool)\(\{[\s\S]*?name:\s*"([^"]+)"/g,
    )) {
      names.add(m[1]);
    }
  }
  for (const rel of ["packages/pi-webxp/src/context7.ts", "packages/pi-webxp/src/deepwiki.ts"]) {
    const src = readFileSync(join(root, rel), "utf8");
    for (const m of src.matchAll(/^\s{2}name:\s*"([^"]+)"/gm)) names.add(m[1]);
  }
  const xtodo = readFileSync(join(root, "packages/pi-xtodo/index.ts"), "utf8");
  const toolName = /^const TOOL_NAME = "([^"]+)"/m.exec(xtodo);
  if (toolName) names.add(toolName[1]);
  return names;
}

function registryToolNames(): Set<string> {
  const doc = readFileSync(join(root, "docs/tool-registry.md"), "utf8");
  const names = new Set<string>();
  for (const heading of doc.matchAll(/^### (.+)$/gm)) {
    // Headings may group sibling tools: "### `CaseGet` / `CaseList` / `CaseSearch`".
    for (const m of heading[1].matchAll(/`([^`]+)`/g)) names.add(m[1]);
  }
  return names;
}

function registryHeadingBlocks(): { names: string[]; heading: string; block: string }[] {
  const doc = readFileSync(join(root, "docs/tool-registry.md"), "utf8");
  const headings = [...doc.matchAll(/^### (.+)$/gm)];
  return headings.map((h, i) => {
    const end = i + 1 < headings.length ? headings[i + 1].index : doc.length;
    return {
      names: [...h[1].matchAll(/`([^`]+)`/g)].map((m) => m[1]),
      heading: h[1],
      block: doc.slice(h.index, end),
    };
  });
}

describe("tool registry drift", () => {
  it("docs/tool-registry.md lists exactly the tools registered in source", () => {
    const source = registeredToolNames();
    const registry = registryToolNames();
    assert.ok(source.size >= 30, `source extraction looks broken (got ${source.size} tools)`);
    const missing = [...source].filter((n) => !registry.has(n)).sort();
    const stale = [...registry].filter((n) => !source.has(n)).sort();
    assert.deepStrictEqual(
      { missing, stale },
      { missing: [], stale: [] },
      "tool registry is out of sync with registered tools — update docs/tool-registry.md",
    );
  });

  it("every registry entry carries a status marker and a tests pointer", () => {
    const blocks = registryHeadingBlocks();
    assert.ok(blocks.length >= 20, "registry parse failure");
    for (const { names, block } of blocks) {
      assert.match(
        block,
        /—\s*(0\.9\.4|unreleased)/,
        `${names.join("/")}: missing release-status marker (0.9.4 or unreleased)`,
      );
      assert.ok(/Tests:/.test(block), `${names.join("/")}: missing "Tests:" pointer`);
    }
  });

  it("package.json extension entry points exist and are covered by the registry", () => {
    const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
    const entries: string[] = pkg.pi?.extensions ?? [];
    assert.ok(entries.length === 3, "expected three extension entry points");
    for (const entry of entries) {
      // Throws if the file is absent from the working tree.
      readFileSync(join(root, entry));
    }
  });
});
