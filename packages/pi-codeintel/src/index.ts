/**
 * pi-codeintel — AST-based TypeScript/JavaScript code intelligence indexer and query suite for Pi Agent.
 *
 * Designed to build a structural model of the codebase (symbols, call graphs, imports, and layout)
 * with a fully lazy-loaded implementation to keep agent startup overhead near zero.
 */

import { createHash } from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Text } from "@earendil-works/pi-tui";
import { Type } from "@sinclair/typebox";
import type { DatabaseSync } from "@xaccefy/pi-sqlite-compat";

// ── Lazy Load Helpers ───────────────────────────────────────────────

let tsInstance: any = null;
async function getTs() {
  if (!tsInstance) {
    const mod = await import("typescript");
    tsInstance = mod.default || mod;
  }
  return tsInstance;
}

const dbInstances = new Map<string, DatabaseSync>();

function getDbPath(workspace: string): string {
  const piDir = path.join(workspace, ".pi");
  if (!fs.existsSync(piDir)) {
    try {
      fs.mkdirSync(piDir, { recursive: true });
    } catch {}
  }
  return path.join(piDir, "codebase.db");
}

async function getDb(workspace: string): Promise<DatabaseSync> {
  const absWorkspace = path.resolve(workspace);
  const cached = dbInstances.get(absWorkspace);
  if (cached) return cached;

  const { DatabaseSync } = await import("@xaccefy/pi-sqlite-compat");
  const dbPath = getDbPath(absWorkspace);
  const db = new DatabaseSync(dbPath);

  // Initialize Schema
  db.exec(`
    CREATE TABLE IF NOT EXISTS files (
      path TEXT PRIMARY KEY,
      hash TEXT NOT NULL,
      size INTEGER NOT NULL,
      summary TEXT,
      updated_at TEXT NOT NULL
    );
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS symbols (
      id TEXT PRIMARY KEY,
      file_path TEXT NOT NULL,
      name TEXT NOT NULL,
      kind TEXT NOT NULL,
      start_line INTEGER NOT NULL,
      end_line INTEGER NOT NULL,
      docstring TEXT,
      signature TEXT,
      FOREIGN KEY(file_path) REFERENCES files(path) ON DELETE CASCADE
    );
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS calls (
      caller_id TEXT,
      callee_name TEXT NOT NULL,
      file_path TEXT NOT NULL,
      line INTEGER NOT NULL,
      FOREIGN KEY(caller_id) REFERENCES symbols(id) ON DELETE CASCADE
    );
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS imports (
      file_path TEXT NOT NULL,
      module_name TEXT NOT NULL,
      symbol_name TEXT NOT NULL,
      FOREIGN KEY(file_path) REFERENCES files(path) ON DELETE CASCADE
    );
  `);

  // Create Indexes
  db.exec(`CREATE INDEX IF NOT EXISTS idx_symbols_name ON symbols(name);`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_symbols_file ON symbols(file_path);`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_calls_callee ON calls(callee_name);`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_calls_caller ON calls(caller_id);`);

  dbInstances.set(absWorkspace, db);
  return db;
}

// ── File Hashing & Walking ──────────────────────────────────────────

function getFileHash(content: string): string {
  return createHash("sha256").update(content).digest("hex");
}

function walkDir(dir: string, callback: (filePath: string) => void) {
  let files: string[] = [];
  try {
    files = fs.readdirSync(dir);
  } catch {
    return;
  }

  for (const file of files) {
    const fullPath = path.join(dir, file);
    let stat: fs.Stats;
    try {
      stat = fs.statSync(fullPath);
    } catch {
      continue;
    }

    if (stat.isDirectory()) {
      if (
        file === "node_modules" ||
        file === ".git" ||
        file === "dist" ||
        file === "build" ||
        file === ".pi" ||
        file === ".gemini"
      ) {
        continue;
      }
      walkDir(fullPath, callback);
    } else if (stat.isFile()) {
      const ext = path.extname(file);
      if (ext === ".ts" || ext === ".js" || ext === ".tsx" || ext === ".jsx") {
        callback(fullPath);
      }
    }
  }
}

// ── AST Parser using TypeScript Compiler API ───────────────────────

interface ParsedSymbol {
  name: string;
  kind: string;
  startLine: number;
  endLine: number;
  docstring: string;
  signature: string;
}

interface ParsedCall {
  callerName: string;
  calleeName: string;
  line: number;
}

interface ParsedImport {
  moduleName: string;
  symbolName: string;
}

function parseSourceFile(ts: any, filePath: string, content: string) {
  const sourceFile = ts.createSourceFile(filePath, content, ts.ScriptTarget.Latest, true);

  const symbols: ParsedSymbol[] = [];
  const calls: ParsedCall[] = [];
  const imports: ParsedImport[] = [];

  let currentFunction: string | null = null;

  function getDocstring(node: any): string {
    const sourceText = sourceFile.text;
    const jsDocComments = ts.getJSDocCommentsAndTags(node);
    if (jsDocComments && jsDocComments.length > 0) {
      return jsDocComments.map((c: any) => c.getText(sourceFile)).join("\n");
    }
    const commentRanges = ts.getLeadingCommentRanges(sourceText, node.pos);
    if (commentRanges && commentRanges.length > 0) {
      return commentRanges.map((r: any) => sourceText.slice(r.pos, r.end)).join("\n");
    }
    return "";
  }

  function getLineOfPos(pos: number): number {
    const { line } = sourceFile.getLineAndCharacterOfPosition(pos);
    return line + 1;
  }

  function visit(node: any) {
    if (ts.isImportDeclaration(node)) {
      const moduleName = node.moduleSpecifier.getText(sourceFile).replace(/['"]/g, "");
      if (node.importClause) {
        if (node.importClause.name) {
          imports.push({ moduleName, symbolName: node.importClause.name.text });
        }
        if (node.importClause.namedBindings) {
          if (ts.isNamedImports(node.importClause.namedBindings)) {
            for (const element of node.importClause.namedBindings.elements) {
              imports.push({ moduleName, symbolName: element.name.text });
            }
          } else if (ts.isNamespaceImport(node.importClause.namedBindings)) {
            imports.push({ moduleName, symbolName: node.importClause.namedBindings.name.text });
          }
        }
      }
    }

    let isDecl = false;
    let name = "";
    let kind = "";
    let signature = "";
    const savedFunction = currentFunction;

    if (ts.isClassDeclaration(node) && node.name) {
      name = node.name.text;
      kind = "Class";
      isDecl = true;
      signature = `class ${name}`;
    } else if (ts.isFunctionDeclaration(node) && node.name) {
      name = node.name.text;
      kind = "Function";
      isDecl = true;
      currentFunction = name;
      signature = node.getText(sourceFile).split("{")[0].trim();
    } else if (ts.isMethodDeclaration(node) && node.name) {
      name = node.name.getText(sourceFile);
      kind = "Method";
      isDecl = true;
      currentFunction = name;
      signature = node.getText(sourceFile).split("{")[0].trim();
    } else if (ts.isInterfaceDeclaration(node) && node.name) {
      name = node.name.text;
      kind = "Interface";
      isDecl = true;
      signature = `interface ${name}`;
    }

    if (isDecl && name) {
      const startLine = getLineOfPos(node.getStart(sourceFile));
      const endLine = getLineOfPos(node.getEnd());
      symbols.push({
        name,
        kind,
        startLine,
        endLine,
        docstring: getDocstring(node),
        signature,
      });
    }

    if (ts.isCallExpression(node)) {
      const callee = node.expression;
      let calleeName = "";
      if (ts.isIdentifier(callee)) {
        calleeName = callee.text;
      } else if (ts.isPropertyAccessExpression(callee)) {
        calleeName = callee.name.text;
      }
      if (calleeName) {
        calls.push({
          callerName: currentFunction || "(global)",
          calleeName,
          line: getLineOfPos(node.getStart(sourceFile)),
        });
      }
    }

    ts.forEachChild(node, visit);
    currentFunction = savedFunction;
  }

  visit(sourceFile);
  return { symbols, calls, imports };
}

// ── Tools Schema ────────────────────────────────────────────────────

const WorkspaceSchema = Type.Object({
  workspace: Type.Optional(
    Type.String({ description: "Target workspace path (default: current directory)" }),
  ),
});

const IndexSchema = Type.Object({
  workspace: Type.Optional(Type.String({ description: "Target workspace path" })),
  force: Type.Optional(Type.Boolean({ description: "Force re-index of all files" })),
});

const FindSymbolSchema = Type.Object({
  query: Type.String({ description: "Search query for symbol names (case-insensitive)" }),
  kind: Type.Optional(
    Type.String({ description: "Filter by symbol kind (Class, Function, Method, etc.)" }),
  ),
  workspace: Type.Optional(Type.String()),
});

const GetSymbolSchema = Type.Object({
  symbolName: Type.String({ description: "The symbol name to trace or query" }),
  workspace: Type.Optional(Type.String()),
});

const CallGraphSchema = Type.Object({
  symbolName: Type.String({ description: "The starting symbol name" }),
  direction: Type.Union([Type.Literal("inbound"), Type.Literal("outbound")], {
    description: "Call trace direction",
  }),
  depth: Type.Optional(Type.Number({ description: "Max call graph traversal depth (default: 3)" })),
  workspace: Type.Optional(Type.String()),
});

const TraceCallPathSchema = Type.Object({
  targetSymbol: Type.String({
    description: "Name of the target function/symbol to trace paths leading to",
  }),
  sourceSymbol: Type.Optional(
    Type.String({ description: "Optional starting function/symbol name to filter paths from" }),
  ),
  workspace: Type.Optional(Type.String()),
});

// ── Indexing Engine (extracted for reuse by ensureIndexed) ───────────

type IndexResult = {
  totalFiles: number;
  updatedFiles: number;
  skippedFiles: number;
  totalSymbols: number;
  totalCalls: number;
};

async function indexWorkspace(
  db: DatabaseSync,
  ts: any,
  absRoot: string,
  force: boolean,
): Promise<IndexResult> {
  let totalFiles = 0;
  let updatedFiles = 0;
  let skippedFiles = 0;

  const filePaths: string[] = [];
  walkDir(absRoot, (p) => filePaths.push(p));

  const selectFile = db.prepare("SELECT hash FROM files WHERE path = ?");
  const deleteFile = db.prepare("DELETE FROM files WHERE path = ?");
  const deleteSymbols = db.prepare("DELETE FROM symbols WHERE file_path = ?");
  const deleteCalls = db.prepare("DELETE FROM calls WHERE file_path = ?");
  const deleteImports = db.prepare("DELETE FROM imports WHERE file_path = ?");

  const insertFile = db.prepare(
    "INSERT INTO files (path, hash, size, summary, updated_at) VALUES (?, ?, ?, ?, ?)",
  );
  const insertSymbol = db.prepare(
    "INSERT OR REPLACE INTO symbols (id, file_path, name, kind, start_line, end_line, docstring, signature) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
  );
  const insertCall = db.prepare(
    "INSERT INTO calls (caller_id, callee_name, file_path, line) VALUES (?, ?, ?, ?)",
  );
  const insertImport = db.prepare(
    "INSERT INTO imports (file_path, module_name, symbol_name) VALUES (?, ?, ?)",
  );

  for (const p of filePaths) {
    totalFiles++;
    const relPath = path.relative(absRoot, p);
    let content = "";
    try {
      content = fs.readFileSync(p, "utf-8");
    } catch {
      skippedFiles++;
      continue;
    }

    const size = statSafe(p)?.size ?? 0;
    const hash = getFileHash(content);

    const existing = selectFile.get(relPath);
    if (!force && existing && existing.hash === hash) {
      skippedFiles++;
      continue;
    }

    try {
      updatedFiles++;

      // Transactional clear
      deleteFile.run(relPath);
      deleteSymbols.run(relPath);
      deleteCalls.run(relPath);
      deleteImports.run(relPath);

      // Parse
      const { symbols, calls, imports } = parseSourceFile(ts, relPath, content);

      insertFile.run(relPath, hash, size, null, new Date().toISOString());

      const symbolIdMap = new Map<string, string>();
      for (const sym of symbols) {
        // Include startLine to guarantee uniqueness (overloads, same-named methods in
        // different classes, etc. would otherwise collide on the PRIMARY KEY).
        const symId = `${relPath}:${sym.name}:${sym.kind}:${sym.startLine}`;
        symbolIdMap.set(sym.name, symId);
        insertSymbol.run(
          symId,
          relPath,
          sym.name,
          sym.kind,
          sym.startLine,
          sym.endLine,
          sym.docstring || null,
          sym.signature || null,
        );
      }

      for (const call of calls) {
        const callerId =
          symbolIdMap.get(call.callerName) || `${relPath}:${call.callerName}:(global)`;
        insertCall.run(callerId, call.calleeName, relPath, call.line);
      }

      for (const imp of imports) {
        insertImport.run(relPath, imp.moduleName, imp.symbolName);
      }
    } catch {
      // A single unparseable file must not crash the entire index
      skippedFiles++;
    }
  }

  // Cleanup files that no longer exist on disk
  const allIndexedFiles = db.prepare("SELECT path FROM files").all() as { path: string }[];
  for (const f of allIndexedFiles) {
    const full = path.join(absRoot, f.path);
    if (!fs.existsSync(full)) {
      deleteFile.run(f.path);
      deleteSymbols.run(f.path);
      deleteCalls.run(f.path);
      deleteImports.run(f.path);
    }
  }

  const totalSymbols = db.prepare("SELECT count(*) as count FROM symbols").get().count;
  const totalCalls = db.prepare("SELECT count(*) as count FROM calls").get().count;

  return { totalFiles, updatedFiles, skippedFiles, totalSymbols, totalCalls };
}

/**
 * Ensure the workspace has been indexed. If the DB is empty (no files),
 * run a full index automatically so query tools work on first call
 * without the agent needing to explicitly call CodebaseIndex first.
 */
async function ensureIndexed(workspace: string): Promise<DatabaseSync> {
  const db = await getDb(workspace);
  const fileCount = db.prepare("SELECT count(*) as count FROM files").get().count;
  if (fileCount === 0) {
    const ts = await getTs();
    await indexWorkspace(db, ts, path.resolve(workspace), false);
  }
  return db;
}

// ── Extension Entry Point ───────────────────────────────────────────

export default function codebaseExtension(pi: ExtensionAPI) {
  // ── Tool: CodebaseIndex ──
  pi.registerTool({
    name: "CodebaseIndex",
    label: "Index Codebase",
    description:
      "Scan and build/update a persistent AST-based SQLite codebase index of the workspace.",
    parameters: IndexSchema,

    async execute(_id, params, _signal, _onUpdate, _ctx) {
      const workspace = (params.workspace as string) || process.cwd();
      const force = params.force === true;

      const db = await getDb(workspace);
      const ts = await getTs();
      const absRoot = path.resolve(workspace);

      const result = await indexWorkspace(db, ts, absRoot, force);

      return {
        content: [
          {
            type: "text" as const,
            text:
              `Incremental indexing complete for: ${absRoot}\n` +
              `  - Total files on disk: ${result.totalFiles}\n` +
              `  - Parsed & updated: ${result.updatedFiles}\n` +
              `  - Skipped (unchanged): ${result.skippedFiles}\n` +
              `  - Database symbols: ${result.totalSymbols}\n` +
              `  - Database call edges: ${result.totalCalls}\n` +
              `Ledger: ${getDbPath(workspace)}`,
          },
        ],
        details: result,
      };
    },

    renderResult(result, _options, theme) {
      const details = result.details as any;
      return new Text(
        theme.fg(
          "success",
          `✓ Indexed: ${details?.totalFiles ?? 0} files (${details?.updatedFiles ?? 0} updated, ${details?.totalSymbols ?? 0} symbols)`,
        ),
        0,
        0,
      );
    },
  });

  // ── Tool: CodebaseFindSymbol ──
  pi.registerTool({
    name: "CodebaseFindSymbol",
    label: "Find Symbol",
    description: "Search for symbols in the index matching a pattern or kind.",
    parameters: FindSymbolSchema,

    async execute(_id, params, _signal, _onUpdate, _ctx) {
      const workspace = (params.workspace as string) || process.cwd();
      const db = await ensureIndexed(workspace);
      // Escape LIKE wildcards so user searches for literal "%" or "_" work correctly
      const escapedQuery = (params.query as string).replace(/[%_]/g, (char) => `\\${char}`);
      const query = `%${escapedQuery}%`;
      const kind = params.kind as string | undefined;

      let rows: any[] = [];
      if (kind) {
        const stmt = db.prepare(
          "SELECT * FROM symbols WHERE name LIKE ? ESCAPE '\\' AND kind = ? LIMIT 100",
        );
        rows = stmt.all(query, kind);
      } else {
        const stmt = db.prepare("SELECT * FROM symbols WHERE name LIKE ? ESCAPE '\\' LIMIT 100");
        rows = stmt.all(query);
      }

      if (rows.length === 0) {
        return {
          content: [{ type: "text", text: `No symbols found matching "${params.query}".` }],
          details: { matches: [] },
        };
      }

      const lines = [`Found ${rows.length} symbol matches:`];
      for (const row of rows) {
        lines.push("");
        lines.push(`• [${row.kind}] ${row.name}`);
        lines.push(`  Path: ${row.file_path}#L${row.start_line}-${row.end_line}`);
        if (row.signature) lines.push(`  Signature: ${row.signature}`);
        if (row.docstring) {
          const doc =
            row.docstring.length > 150 ? `${row.docstring.slice(0, 150)}...` : row.docstring;
          lines.push(`  Docs: ${doc}`);
        }
      }

      return {
        content: [{ type: "text", text: lines.join("\n") }],
        details: { matches: rows },
      };
    },
  });

  // ── Tool: CodebaseGetDefinition ──
  pi.registerTool({
    name: "CodebaseGetDefinition",
    label: "Get Definition",
    description: "Find the declaration details and source code of a symbol.",
    parameters: GetSymbolSchema,

    async execute(_id, params, _signal, _onUpdate, _ctx) {
      const workspace = (params.workspace as string) || process.cwd();
      const db = await ensureIndexed(workspace);
      const name = params.symbolName as string;

      const stmt = db.prepare("SELECT * FROM symbols WHERE name = ? LIMIT 5");
      const rows = stmt.all(name) as any[];

      if (rows.length === 0) {
        return {
          content: [{ type: "text", text: `Symbol "${name}" not found.` }],
          details: { found: false },
        };
      }

      const lines: string[] = [];
      for (const row of rows) {
        lines.push(`### [${row.kind}] ${row.name}`);
        lines.push(`File: ${row.file_path}:${row.start_line}-${row.end_line}`);
        if (row.signature) lines.push(`Signature: \`${row.signature}\``);
        lines.push("");

        // Try reading source lines
        const fullPath = path.join(workspace, row.file_path);
        if (fs.existsSync(fullPath)) {
          try {
            const contentLines = fs.readFileSync(fullPath, "utf-8").split("\n");
            const start = Math.max(0, row.start_line - 1);
            const end = Math.min(contentLines.length, row.end_line);
            const snippet = contentLines.slice(start, end).join("\n");
            lines.push("```typescript");
            lines.push(snippet);
            lines.push("```");
          } catch {}
        }
        lines.push("\n---");
      }

      return {
        content: [{ type: "text", text: lines.join("\n") }],
        details: { found: true, symbols: rows },
      };
    },
  });

  // ── Tool: CodebaseFindReferences ──
  pi.registerTool({
    name: "CodebaseFindReferences",
    label: "Find References",
    description: "Search for all code locations calling or referencing a symbol.",
    parameters: GetSymbolSchema,

    async execute(_id, params, _signal, _onUpdate, _ctx) {
      const workspace = (params.workspace as string) || process.cwd();
      const db = await ensureIndexed(workspace);
      const name = params.symbolName as string;

      const stmt = db.prepare(`
        SELECT c.callee_name, c.file_path, c.line, s.name as caller_name, s.kind as caller_kind
        FROM calls c
        LEFT JOIN symbols s ON c.caller_id = s.id
        WHERE c.callee_name = ?
        LIMIT 150
      `);
      const rows = stmt.all(name) as any[];

      if (rows.length === 0) {
        return {
          content: [{ type: "text", text: `No references found calling "${name}".` }],
          details: { references: [] },
        };
      }

      const lines = [`References to "${name}":`];
      for (const row of rows) {
        const callerText = row.caller_name
          ? `${row.caller_name} (${row.caller_kind})`
          : "(global/anonymous)";
        lines.push(`  - ${row.file_path}:${row.line} in ${callerText}`);
      }

      return {
        content: [{ type: "text", text: lines.join("\n") }],
        details: { references: rows },
      };
    },
  });

  // ── Tool: CodebaseGetCallGraph ──
  pi.registerTool({
    name: "CodebaseGetCallGraph",
    label: "Get Call Graph",
    description: "Trace inbound or outbound call pathways for a symbol.",
    parameters: CallGraphSchema,

    async execute(_id, params, _signal, _onUpdate, _ctx) {
      const workspace = (params.workspace as string) || process.cwd();
      const db = await ensureIndexed(workspace);
      const startSym = params.symbolName as string;
      const direction = params.direction as "inbound" | "outbound";
      const depth = (params.depth as number | undefined) ?? 3;

      const visited = new Set<string>();
      const lines: string[] = [`Call Graph for "${startSym}" (${direction}, max depth ${depth}):`];

      function traceInbound(callee: string, currentDepth: number, indent: string) {
        if (currentDepth > depth || visited.has(callee)) return;
        visited.add(callee);

        const stmt = db.prepare(`
          SELECT s.name as caller, s.kind, c.file_path, c.line
          FROM calls c
          JOIN symbols s ON c.caller_id = s.id
          WHERE c.callee_name = ?
        `);
        const callers = stmt.all(callee) as any[];

        for (const c of callers) {
          lines.push(`${indent}↖ ${c.caller} [${c.kind}] (${c.file_path}:${c.line})`);
          traceInbound(c.caller, currentDepth + 1, `${indent}  `);
        }
      }

      function traceOutbound(callerName: string, currentDepth: number, indent: string) {
        if (currentDepth > depth || visited.has(callerName)) return;
        visited.add(callerName);

        // Find the caller symbol id(s)
        const symStmt = db.prepare("SELECT id FROM symbols WHERE name = ?");
        const syms = symStmt.all(callerName) as { id: string }[];

        for (const s of syms) {
          const callStmt = db.prepare(`
            SELECT callee_name, line, file_path
            FROM calls
            WHERE caller_id = ?
          `);
          const callees = callStmt.all(s.id) as any[];
          for (const c of callees) {
            lines.push(`${indent}↘ ${c.callee_name} (${c.file_path}:${c.line})`);
            traceOutbound(c.callee_name, currentDepth + 1, `${indent}  `);
          }
        }
      }

      if (direction === "inbound") {
        traceInbound(startSym, 1, "  ");
      } else {
        traceOutbound(startSym, 1, "  ");
      }

      if (lines.length === 1) {
        lines.push("  (No relationships mapped)");
      }

      return {
        content: [{ type: "text", text: lines.join("\n") }],
        details: { startSym, direction, depth },
      };
    },
  });

  // ── Tool: CodebaseTraceCallPath ──
  pi.registerTool({
    name: "CodebaseTraceCallPath",
    label: "Trace Call Path",
    description:
      "Scan call graph database paths to trace call routes leading to a target function or symbol.",
    parameters: TraceCallPathSchema,

    async execute(_id, params, _signal, _onUpdate, _ctx) {
      const workspace = (params.workspace as string) || process.cwd();
      const db = await ensureIndexed(workspace);
      const target = params.targetSymbol as string;
      const sourceFilter = params.sourceSymbol as string | undefined;

      // Find call edges where callee is the target
      const stmt = db.prepare(`
        SELECT c.caller_id, s.name as caller_name, c.file_path, c.line
        FROM calls c
        JOIN symbols s ON c.caller_id = s.id
        WHERE c.callee_name = ?
      `);
      const directCallers = stmt.all(target) as any[];

      if (directCallers.length === 0) {
        return {
          content: [{ type: "text", text: `No call paths found leading to symbol: "${target}"` }],
          details: { paths: [] },
        };
      }

      const paths: string[][] = [];
      const MAX_PATHS = 50; // Cap to prevent context flooding on large call graphs

      function findPathsUpTo(callerId: string, currentPath: string[], visited: Set<string>) {
        if (paths.length >= MAX_PATHS) return; // Stop exploring once we hit the cap
        if (visited.has(callerId)) return;
        const nextVisited = new Set(visited);
        nextVisited.add(callerId);

        const symStmt = db.prepare("SELECT name FROM symbols WHERE id = ?");
        const sym = symStmt.get(callerId);
        if (!sym) return;

        const name = sym.name;
        const newPath = [name, ...currentPath];

        if (sourceFilter && name.toLowerCase().includes(sourceFilter.toLowerCase())) {
          paths.push(newPath);
          return;
        }

        // Trace further up: who calls this symbol?
        const callersStmt = db.prepare(`
          SELECT caller_id
          FROM calls
          WHERE callee_name = ?
        `);
        const callers = callersStmt.all(name) as { caller_id: string }[];

        if (callers.length === 0) {
          if (!sourceFilter) {
            paths.push(newPath);
          }
          return;
        }

        for (const c of callers) {
          if (paths.length >= MAX_PATHS) break; // Check before recursing
          findPathsUpTo(c.caller_id, newPath, nextVisited);
        }
      }

      for (const caller of directCallers) {
        if (paths.length >= MAX_PATHS) break;
        findPathsUpTo(caller.caller_id, [target], new Set());
      }

      const lines = [`Call pathways leading to symbol: "${target}":`];
      for (const p of paths) {
        lines.push(`  • ${p.join(" ──→ ")}`);
      }

      if (paths.length === 0) {
        lines.push("  (No complete paths matched the source filter criteria)");
      } else if (paths.length >= MAX_PATHS) {
        lines.push(`  (Showing first ${MAX_PATHS} paths; more may exist)`);
      }

      return {
        content: [{ type: "text", text: lines.join("\n") }],
        details: { paths, target, sourceFilter, capped: paths.length >= MAX_PATHS },
      };
    },
  });

  // ── Tool: CodebaseGetArchitecture ──
  pi.registerTool({
    name: "CodebaseGetArchitecture",
    label: "Get Codebase Architecture",
    description: "Summarize top-level directory layout, key imports, and hotspot functions.",
    parameters: WorkspaceSchema,

    async execute(_id, params, _signal, _onUpdate, _ctx) {
      const workspace = (params.workspace as string) || process.cwd();
      const db = await ensureIndexed(workspace);

      // Top Hotspot Functions (Highest Inbound Call Count)
      const hotspotStmt = db.prepare(`
        SELECT c.callee_name, count(*) as call_count, s.file_path, s.kind
        FROM calls c
        LEFT JOIN symbols s ON s.name = c.callee_name
        GROUP BY c.callee_name
        ORDER BY call_count DESC
        LIMIT 10
      `);
      const hotspots = hotspotStmt.all() as any[];

      // Top Modules Imported
      const importStmt = db.prepare(`
        SELECT module_name, count(*) as import_count
        FROM imports
        GROUP BY module_name
        ORDER BY import_count DESC
        LIMIT 10
      `);
      const topImports = importStmt.all() as any[];

      // General counts
      const counts = db
        .prepare(`
        SELECT 
          (SELECT count(*) FROM files) as files_count,
          (SELECT count(*) FROM symbols) as symbols_count,
          (SELECT count(*) FROM calls) as calls_count
      `)
        .get();

      const lines = [
        `Codebase Architecture Summary for: ${workspace}`,
        `Indexed Corpus:`,
        `  - Files: ${counts?.files_count ?? 0}`,
        `  - AST Symbols: ${counts?.symbols_count ?? 0}`,
        `  - Call Graph Edges: ${counts?.calls_count ?? 0}`,
        ``,
        `Hotspot Functions (most calls):`,
      ];

      for (const h of hotspots) {
        const loc = h.file_path ? ` (${h.file_path})` : "";
        lines.push(`  - ${h.callee_name} (called ${h.call_count}x)${loc}`);
      }

      lines.push(``, `Top Internal/External Dependencies (frequent imports):`);

      for (const i of topImports) {
        lines.push(`  - "${i.module_name}" (imported ${i.import_count}x)`);
      }

      return {
        content: [{ type: "text", text: lines.join("\n") }],
        details: { hotspots, topImports, counts },
      };
    },
  });
}

// Helper: safe file stat
function statSafe(p: string): fs.Stats | null {
  try {
    return fs.statSync(p);
  } catch {
    return null;
  }
}
