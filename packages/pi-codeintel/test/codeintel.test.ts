import { afterEach, beforeEach, describe, it } from "node:test";
import assert from "node:assert";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";
import codebaseExtension from "../src/index.ts";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

class MockExtensionAPI {
  tools: any[] = [];
  events: Record<string, Function[]> = {};

  registerTool(spec: any) {
    this.tools.push(spec);
  }

  on(event: string, handler: Function) {
    if (!this.events[event]) this.events[event] = [];
    this.events[event].push(handler);
  }
}

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
      `
    );

    // File B: has helper that calls eval
    fs.writeFileSync(
      path.join(tempDir, "fileB.ts"),
      `
      export function helper() {
        const input = "1 + 1";
        eval(input);
      }
      `
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
    const indexResult = await indexTool.execute("call-1", { workspace: tempDir, force: true }, null, null, null);
    assert.strictEqual(indexResult.details.totalFiles, 2);
    assert.strictEqual(indexResult.details.updatedFiles, 2);

    // 2. Find Symbol
    const findResult = await findSymbolTool.execute("call-2", { query: "main", workspace: tempDir }, null, null, null);
    assert.ok(findResult.details.matches.length > 0);
    assert.strictEqual(findResult.details.matches[0].name, "main");

    // 3. Find References (who calls helper?)
    const refResult = await findRefTool.execute("call-3", { symbolName: "helper", workspace: tempDir }, null, null, null);
    assert.ok(refResult.details.references.length > 0);
    assert.strictEqual(refResult.details.references[0].file_path, "fileA.ts");

    // 4. Trace Call Path (who eventually reaches eval?)
    const pathResult = await traceCallPathTool.execute("call-4", { targetSymbol: "eval", workspace: tempDir }, null, null, null);
    assert.ok(pathResult.details.paths.length > 0);
    // Path should be main -> helper -> eval
    const pathStr = pathResult.content[0].text;
    assert.ok(pathStr.includes("main"));
    assert.ok(pathStr.includes("helper"));
    assert.ok(pathStr.includes("eval"));

    // 5. Get Architecture summary
    const archResult = await getArchTool.execute("call-5", { workspace: tempDir }, null, null, null);
    assert.strictEqual(archResult.details.counts.files_count, 2);
  });
});
