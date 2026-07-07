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
import { DatabaseSync } from "./sqlite-compat/index.ts";

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

  const dbPath = getDbPath(absWorkspace);
  const db = new DatabaseSync(dbPath);
  // Enable foreign-key enforcement so ON DELETE CASCADE actually fires
  // (SQLite keeps FK off by default; bun:sqlite in particular defaults it off).
  db.exec("PRAGMA foreign_keys = ON");

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
      callee_id TEXT,
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
  // Backfill callee_id on databases indexed before this column existed. New indexes
  // populate it directly; older rows keep callee_id NULL and queries fall back to name.
  try {
    db.exec(`ALTER TABLE calls ADD COLUMN callee_id TEXT`);
  } catch {
    // Column already present.
  }
  db.exec(`CREATE INDEX IF NOT EXISTS idx_calls_callee_id ON calls(callee_id);`);

  dbInstances.set(absWorkspace, db);
  return db;
}

// ── File Hashing & Walking ──────────────────────────────────────────

function getFileHash(content: string): string {
  // SHA-1 is faster than SHA-256; sufficient for dedup (not crypto)
  return createHash("sha1").update(content).digest("hex");
}

/** Read .gitignore patterns from a directory, returning an array of glob-like patterns. */
function readGitignore(dir: string): string[] {
  const gitignorePath = path.join(dir, ".gitignore");
  try {
    const content = fs.readFileSync(gitignorePath, "utf-8");
    return content
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith("#"))
      .map((l) => l.replace(/\/$/, "")); // strip trailing slash
  } catch {
    return [];
  }
}

/** Check if a filename or relative path matches any gitignore pattern. */
function matchesIgnore(name: string, patterns: string[]): boolean {
  for (const p of patterns) {
    if (p.startsWith("/")) {
      if (name === p.slice(1)) return true;
    } else if (name === p || name.endsWith(`/${p}`) || name.startsWith(p + "/")) {
      return true;
    }
  }
  return false;
}

const MAX_FILE_SIZE = 1_048_576; // skip files > 1MB (bundles, minified, generated)

const SKIP_DIRS = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  ".pi",
  ".gemini",
  ".cache",
  ".next",
  ".turbo",
  ".nyc_output",
  "coverage",
  ".codebase-memory",
  "__pycache__",
  ".venv",
  ".tox",
  "__generated__",
  "generated",
  ".generated",
  "third_party",
  "vendor",
  "bower_components",
  "cdn_modules",
  "compiled",
]);

const INDEX_EXT = new Set([".ts", ".js", ".tsx", ".jsx", ".mjs", ".cjs", ".mts", ".cts"]);

function walkDir(
  dir: string,
  callback: (filePath: string) => void,
  rootDir = dir,
  gitignorePatterns: string[] | null = null,
) {
  if (gitignorePatterns === null) {
    gitignorePatterns = readGitignore(dir);
  }

  let files: string[] = [];
  try {
    files = fs.readdirSync(dir);
  } catch {
    return;
  }

  // Read nested .gitignore
  const localPatterns = [...gitignorePatterns, ...readGitignore(dir)];

  for (const file of files) {
    const fullPath = path.join(dir, file);
    const relPath = path.relative(rootDir, fullPath);

    if (matchesIgnore(relPath, localPatterns)) continue;

    let stat: fs.Stats;
    try {
      stat = fs.statSync(fullPath);
    } catch {
      continue;
    }

    if (stat.isDirectory()) {
      if (SKIP_DIRS.has(file)) continue;
      walkDir(fullPath, callback, rootDir, localPatterns);
    } else if (stat.isFile()) {
      // Skip declaration files, minified, and oversized files
      if (file.endsWith(".d.ts") || file.endsWith(".d.mts") || file.endsWith(".d.cts")) continue;
      if (file.includes(".min.") || file.includes("-min.")) continue;
      if (stat.size > MAX_FILE_SIZE || stat.size === 0) continue;

      const ext = path.extname(file);
      if (INDEX_EXT.has(ext)) {
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
    "INSERT INTO calls (caller_id, callee_name, callee_id, file_path, line) VALUES (?, ?, ?, ?, ?)",
  );
  const insertImport = db.prepare(
    "INSERT INTO imports (file_path, module_name, symbol_name) VALUES (?, ?, ?)",
  );

  // Pass 1: parse every file up front so cross-file import resolution has the full
  // symbol table. A callee imported from another module must resolve to THAT module's
  // symbol id (otherwise callee_id is useless for disambiguating same-named functions).
  interface ParsedFile {
    relPath: string;
    hash: string;
    size: number;
    symbols: { name: string; kind: string; startLine: number; endLine: number; docstring?: string; signature?: string }[];
    calls: { callerName: string; calleeName: string; line: number }[];
    imports: { moduleName: string; symbolName: string }[];
  }
  const parsedAll: ParsedFile[] = [];
  const fileSymIds = new Map<string, Map<string, string>>(); // relPath -> (symbol name -> id)

  for (const p of filePaths) {
    const relPath = path.relative(absRoot, p);
    let content = "";
    try {
      content = fs.readFileSync(p, "utf-8");
    } catch {
      skippedFiles++;
      continue;
    }
    const size = statSafe(p)?.size ?? 0;
    if (size === 0 || size > MAX_FILE_SIZE) {
      skippedFiles++;
      continue;
    }
    const hash = getFileHash(content);
    let symbols: ParsedFile["symbols"] = [];
    let calls: ParsedFile["calls"] = [];
    let imports: ParsedFile["imports"] = [];
    try {
      const parsed = parseSourceFile(ts, relPath, content);
      symbols = parsed.symbols;
      calls = parsed.calls;
      imports = parsed.imports;
    } catch {
      skippedFiles++;
      continue;
    }
    const symMap = new Map<string, string>();
    for (const sym of symbols) {
      const symId = `${relPath}:${sym.name}:${sym.kind}:${sym.startLine}`;
      symMap.set(sym.name, symId);
    }
    fileSymIds.set(relPath, symMap);
    parsedAll.push({ relPath, hash, size, symbols, calls, imports });
  }

  // Resolve a relative module specifier ("./fileB", "../x/y") to a known relPath.
  function resolveModule(importerRel: string, moduleName: string): string | null {
    if (!moduleName.startsWith(".")) return null;
    const dir = path.posix.dirname(importerRel);
    const base = path.posix.normalize(path.posix.join(dir, moduleName));
    const candidates = [base, `${base}.ts`, `${base}.tsx`, `${base}.js`, `${base}.jsx`, `${base}/index.ts`];
    for (const c of candidates) if (fileSymIds.has(c)) return c;
    return null;
  }

  db.exec("BEGIN");
  try {
    for (const pf of parsedAll) {
      totalFiles++;
      const existing = selectFile.get(pf.relPath);
      if (!force && existing && existing.hash === pf.hash) {
        skippedFiles++;
        continue;
      }

      try {
        updatedFiles++;

        // Transactional clear
        deleteFile.run(pf.relPath);
        deleteSymbols.run(pf.relPath);
        deleteCalls.run(pf.relPath);
        deleteImports.run(pf.relPath);

        insertFile.run(pf.relPath, pf.hash, pf.size, null, new Date().toISOString());

        for (const sym of pf.symbols) {
          const symId = `${pf.relPath}:${sym.name}:${sym.kind}:${sym.startLine}`;
          insertSymbol.run(
            symId,
            pf.relPath,
            sym.name,
            sym.kind,
            sym.startLine,
            sym.endLine,
            sym.docstring || null,
            sym.signature || null,
          );
        }

        // Map imported names -> the imported module's concrete symbol id.
        const importSym = new Map<string, string>();
        for (const imp of pf.imports) {
          const targetRel = resolveModule(pf.relPath, imp.moduleName);
          if (targetRel) {
            const tid = fileSymIds.get(targetRel)?.get(imp.symbolName);
            if (tid) importSym.set(imp.symbolName, tid);
          }
        }

        const localSym = fileSymIds.get(pf.relPath);
        for (const call of pf.calls) {
          const callerId = localSym?.get(call.callerName) || `${pf.relPath}:${call.callerName}:(global)`;
          // Prefer the imported symbol's id (cross-file), then a same-file symbol,
          // else null (queries fall back to callee_name).
          const calleeId = importSym.get(call.calleeName) ?? localSym?.get(call.calleeName) ?? null;
          insertCall.run(callerId, call.calleeName, calleeId, pf.relPath, call.line);
        }

        for (const imp of pf.imports) {
          insertImport.run(pf.relPath, imp.moduleName, imp.symbolName);
        }
      } catch {
        // A single unparseable file must not crash the entire index
        skippedFiles++;
      }
    }
    db.exec("COMMIT");
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }

  // Cleanup files that no longer exist on disk
  db.exec("BEGIN");
  try {
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
    db.exec("COMMIT");
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
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

      const ids = (db.prepare("SELECT id FROM symbols WHERE name = ?").all(name) as { id: string }[]).map(
        (r) => r.id,
      );
      const inSql = ids.length ? `c.callee_id IN (${ids.map(() => "?").join(",")}) OR ` : "";
      const stmt = db.prepare(`
        SELECT c.callee_name, c.file_path, c.line, s.name as caller_name, s.kind as caller_kind
        FROM calls c
        LEFT JOIN symbols s ON c.caller_id = s.id
        WHERE (${inSql}(c.callee_id IS NULL AND c.callee_name = ?))
        LIMIT 150
      `);
      const rows = stmt.all(...ids, name) as any[];

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

      function traceInbound(calleeId: string, calleeName: string, currentDepth: number, indent: string) {
        if (currentDepth > depth || visited.has(calleeId)) return;
        visited.add(calleeId);

        const stmt = db.prepare(`
          SELECT s.id as caller_id, s.name as caller, s.kind, c.file_path, c.line
          FROM calls c
          JOIN symbols s ON c.caller_id = s.id
          WHERE (c.callee_id = ? OR (c.callee_id IS NULL AND c.callee_name = ?))
        `);
        const callers = stmt.all(calleeId, calleeName) as any[];

        for (const c of callers) {
          lines.push(`${indent}↖ ${c.caller} [${c.kind}] (${c.file_path}:${c.line})`);
          traceInbound(c.caller_id, c.caller, currentDepth + 1, `${indent}  `);
        }
      }

      function traceOutbound(callerId: string, callerName: string, currentDepth: number, indent: string) {
        if (currentDepth > depth || visited.has(callerId)) return;
        visited.add(callerId);

        const callStmt = db.prepare(`
          SELECT callee_id, callee_name, line, file_path
          FROM calls
          WHERE caller_id = ?
        `);
        const callees = callStmt.all(callerId) as any[];
        for (const c of callees) {
          lines.push(`${indent}↘ ${c.callee_name} (${c.file_path}:${c.line})`);
          traceOutbound(c.callee_id ?? c.callee_name, c.callee_name, currentDepth + 1, `${indent}  `);
        }
      }

      const startSyms = db.prepare("SELECT id, name FROM symbols WHERE name = ?").all(startSym) as {
        id: string;
        name: string;
      }[];
      if (startSyms.length === 0) {
        // Symbol not indexed: fall back to a name-only match so the trace still runs.
        if (direction === "inbound") traceInbound(startSym, startSym, 1, "  ");
        else traceOutbound(startSym, startSym, 1, "  ");
      } else if (direction === "inbound") {
        for (const s of startSyms) traceInbound(s.id, s.name, 1, "  ");
      } else {
        for (const s of startSyms) traceOutbound(s.id, s.name, 1, "  ");
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
      const targetIds = (
        db.prepare("SELECT id FROM symbols WHERE name = ?").all(target) as { id: string }[]
      ).map((r) => r.id);
      const targetInSql = targetIds.length
        ? `c.callee_id IN (${targetIds.map(() => "?").join(",")}) OR `
        : "";
      const stmt = db.prepare(`
        SELECT c.caller_id, s.name as caller_name, c.file_path, c.line
        FROM calls c
        JOIN symbols s ON c.caller_id = s.id
        WHERE (${targetInSql}(c.callee_id IS NULL AND c.callee_name = ?))
      `);
      const directCallers = stmt.all(...targetIds, target) as any[];

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
          WHERE (callee_id = ? OR (callee_id IS NULL AND callee_name = ?))
        `);
        const callers = callersStmt.all(callerId, name) as { caller_id: string }[];

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
