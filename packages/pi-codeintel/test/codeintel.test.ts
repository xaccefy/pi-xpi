import assert from "node:assert";
import * as fs from "node:fs";
import * as path from "node:path";
import { dirname } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { MockExtensionAPI } from "../../../test-utils.ts";
import codebaseExtension from "../src/index.ts";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

describe("pi-codeintel tool tests", () => {
  const tempDir = path.join(__dirname, "temp_workspace");

  beforeEach(() => {
    // Set up mock files
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
    fs.mkdirSync(tempDir, { recursive: true });

    // File A: imports b, calls helper
    fs.writeFileSync(
      path.join(tempDir, "fileA.ts"),
      `
      import { helper } from "./fileB";
      
      /**
       * Runs main driver function.
       */
      export function main() {
        console.log("Starting...");
        helper();
      }
      `,
    );

    // File B: has helper that calls eval
    fs.writeFileSync(
      path.join(tempDir, "fileB.ts"),
      `
      export function helper() {
        const input = "1 + 1";
        eval(input);
      }
      `,
    );
  });

  afterEach(() => {
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("indexes codebase and resolves symbols, references, calls, and taint paths", async () => {
    const pi = new MockExtensionAPI();
    codebaseExtension(pi as any);

    const indexTool = pi.tools.find((t) => t.name === "CodebaseIndex");
    const findSymbolTool = pi.tools.find((t) => t.name === "CodebaseFindSymbol");
    const getDefTool = pi.tools.find((t) => t.name === "CodebaseGetDefinition");
    const findRefTool = pi.tools.find((t) => t.name === "CodebaseFindReferences");
    const callGraphTool = pi.tools.find((t) => t.name === "CodebaseGetCallGraph");
    const traceCallPathTool = pi.tools.find((t) => t.name === "CodebaseTraceCallPath");
    const getArchTool = pi.tools.find((t) => t.name === "CodebaseGetArchitecture");

    assert.ok(indexTool);
    assert.ok(findSymbolTool);
    assert.ok(getDefTool);
    assert.ok(findRefTool);
    assert.ok(callGraphTool);
    assert.ok(traceCallPathTool);
    assert.ok(getArchTool);

    // 1. Index the workspace
    const indexResult = await indexTool.execute(
      "call-1",
      { workspace: tempDir, force: true },
      null,
      null,
      null,
    );
    assert.strictEqual(indexResult.details.totalFiles, 2);
    assert.strictEqual(indexResult.details.updatedFiles, 2);

    // 2. Find Symbol
    const findResult = await findSymbolTool.execute(
      "call-2",
      { query: "main", workspace: tempDir },
      null,
      null,
      null,
    );
    assert.ok(findResult.details.matches.length > 0);
    assert.strictEqual(findResult.details.matches[0].name, "main");

    // 3. Find References (who calls helper?)
    const refResult = await findRefTool.execute(
      "call-3",
      { symbolName: "helper", workspace: tempDir },
      null,
      null,
      null,
    );
    assert.ok(refResult.details.references.length > 0);
    assert.strictEqual(refResult.details.references[0].file_path, "fileA.ts");

    // 4. Trace Call Path (who eventually reaches eval?)
    const pathResult = await traceCallPathTool.execute(
      "call-4",
      { targetSymbol: "eval", workspace: tempDir },
      null,
      null,
      null,
    );
    assert.ok(pathResult.details.paths.length > 0);
    // Path should be main -> helper -> eval
    const pathStr = pathResult.content[0].text;
    assert.ok(pathStr.includes("main"));
    assert.ok(pathStr.includes("helper"));
    assert.ok(pathStr.includes("eval"));

    // 5. Get Architecture summary
    const archResult = await getArchTool.execute(
      "call-5",
      { workspace: tempDir },
      null,
      null,
      null,
    );
    assert.strictEqual(archResult.details.counts.files_count, 2);
  });

  it("disambiguates same-named functions across files via callee_id (no false paths)", async () => {
    const collisionDir = path.join(tempDir, "collision");
    fs.mkdirSync(collisionDir, { recursive: true });
    // Two functions named `helper`, in different files, only ONE of which reaches eval.
    fs.writeFileSync(
      path.join(collisionDir, "fileB.ts"),
      `export function helper() { eval("1 + 1"); }`,
    );
    fs.writeFileSync(
      path.join(collisionDir, "fileC.ts"),
      `export function helper() { console.log("other"); }`,
    );
    fs.writeFileSync(
      path.join(collisionDir, "fileA.ts"),
      `import { helper } from "./fileB";\n\nexport function run() { helper(); }`,
    );
    fs.writeFileSync(
      path.join(collisionDir, "fileD.ts"),
      `import { helper } from "./fileC";\n\nexport function otherRun() { helper(); }`,
    );

    const pi = new MockExtensionAPI();
    codebaseExtension(pi as any);
    const indexTool = pi.tools.find((t) => t.name === "CodebaseIndex");
    const traceTool = pi.tools.find((t) => t.name === "CodebaseTraceCallPath");

    await indexTool.execute("i1", { workspace: collisionDir, force: true }, null, null, null);

    const res = await traceTool.execute(
      "t1",
      { targetSymbol: "eval", workspace: collisionDir },
      null,
      null,
      null,
    );
    const text = res.content[0].text;
    assert.ok(text.includes("run"), "real caller 'run' should appear in the path to eval");
    assert.ok(
      !text.toLowerCase().includes("otherrun"),
      "must NOT report otherRun as a path to eval (name-collision false positive)",
    );
    assert.ok(text.includes("helper"), "helper should appear as the intermediate node");
  });
});
