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

// Cap open workspace DBs so long-lived agents don't leak FDs across many roots.
const MAX_DB_INSTANCES = 8;
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

/** Normalize to posix-style relative paths so resolveModule works on Windows too. */
function toPosixRel(p: string): string {
  return p.split(path.sep).join("/");
}

async function getDb(workspace: string): Promise<DatabaseSync> {
  const absWorkspace = path.resolve(workspace);
  const dbPath = getDbPath(absWorkspace);
  const cached = dbInstances.get(absWorkspace);
  if (cached) {
    // If the on-disk DB was wiped (test cleanup / workspace reset), drop the stale handle.
    if (!fs.existsSync(dbPath)) {
      try {
        cached.close();
      } catch {
        // ignore
      }
      dbInstances.delete(absWorkspace);
    } else {
      // Touch for simple LRU: re-insert at end.
      dbInstances.delete(absWorkspace);
      dbInstances.set(absWorkspace, cached);
      return cached;
    }
  }

  // Evict oldest entries when over capacity.
  while (dbInstances.size >= MAX_DB_INSTANCES) {
    const oldest = dbInstances.keys().next().value as string | undefined;
    if (oldest === undefined) break;
    const oldDb = dbInstances.get(oldest);
    dbInstances.delete(oldest);
    try {
      oldDb?.close();
    } catch {
      // Best-effort close.
    }
  }

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
  /** Local binding used at call sites (may be an alias). */
  localName: string;
  /** Exported name in the target module (propertyName, or localName if unaliased). */
  importedName: string;
}

const GLOBAL_CALLER = "(global)";

function parseSourceFile(ts: any, filePath: string, content: string) {
  const sourceFile = ts.createSourceFile(filePath, content, ts.ScriptTarget.Latest, true);

  const symbols: ParsedSymbol[] = [];
  const calls: ParsedCall[] = [];
  const imports: ParsedImport[] = [];

  let currentFunction: string | null = null;
  let currentClass: string | null = null;

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

  function pushSymbol(name: string, kind: string, node: any, signature: string): void {
    symbols.push({
      name,
      kind,
      startLine: getLineOfPos(node.getStart(sourceFile)),
      endLine: getLineOfPos(node.getEnd()),
      docstring: getDocstring(node),
      signature,
    });
  }

  function visit(node: any) {
    if (ts.isImportDeclaration(node)) {
      const moduleName = node.moduleSpecifier.getText(sourceFile).replace(/['"]/g, "");
      if (node.importClause) {
        if (node.importClause.name) {
          // default import: `import Foo from "./m"` — local and imported both "default"-ish
          const local = node.importClause.name.text;
          imports.push({ moduleName, localName: local, importedName: "default" });
        }
        if (node.importClause.namedBindings) {
          if (ts.isNamedImports(node.importClause.namedBindings)) {
            for (const element of node.importClause.namedBindings.elements) {
              const localName = element.name.text;
              // `import { helper as h }` → local h, imported helper
              const importedName = element.propertyName?.text ?? localName;
              imports.push({ moduleName, localName, importedName });
            }
          } else if (ts.isNamespaceImport(node.importClause.namedBindings)) {
            const local = node.importClause.namedBindings.name.text;
            imports.push({ moduleName, localName: local, importedName: "*" });
          }
        }
      }
    }

    const savedFunction = currentFunction;
    const savedClass = currentClass;

    if (ts.isClassDeclaration(node) && node.name) {
      const name = node.name.text;
      pushSymbol(name, "Class", node, `class ${name}`);
      currentClass = name;
      ts.forEachChild(node, visit);
      currentClass = savedClass;
      currentFunction = savedFunction;
      return;
    }

    if (ts.isFunctionDeclaration(node) && node.name) {
      const name = node.name.text;
      pushSymbol(name, "Function", node, node.getText(sourceFile).split("{")[0].trim());
      currentFunction = name;
      ts.forEachChild(node, visit);
      currentFunction = savedFunction;
      return;
    }

    if (ts.isMethodDeclaration(node) && node.name) {
      const methodName = node.name.getText(sourceFile);
      // Qualify methods so ClassA.render and ClassB.render don't collide.
      const name = currentClass ? `${currentClass}.${methodName}` : methodName;
      pushSymbol(name, "Method", node, node.getText(sourceFile).split("{")[0].trim());
      currentFunction = name;
      ts.forEachChild(node, visit);
      currentFunction = savedFunction;
      return;
    }

    if (ts.isConstructorDeclaration(node)) {
      const name = currentClass ? `${currentClass}.constructor` : "constructor";
      pushSymbol(name, "Constructor", node, node.getText(sourceFile).split("{")[0].trim());
      currentFunction = name;
      ts.forEachChild(node, visit);
      currentFunction = savedFunction;
      return;
    }

    if (ts.isInterfaceDeclaration(node) && node.name) {
      pushSymbol(node.name.text, "Interface", node, `interface ${node.name.text}`);
    }

    // const foo = () => {} / const foo = function() {} / let foo = async () => {}
    if (ts.isVariableStatement(node)) {
      for (const decl of node.declarationList.declarations) {
        if (!ts.isIdentifier(decl.name) || !decl.initializer) continue;
        const init = decl.initializer;
        const isFn = ts.isArrowFunction(init) || ts.isFunctionExpression(init);
        if (isFn) {
          const name = decl.name.text;
          pushSymbol(
            name,
            "Function",
            decl,
            `${node.getText(sourceFile).split("{")[0].split("=")[0].trim()} = …`,
          );
          const prev = currentFunction;
          currentFunction = name;
          ts.forEachChild(init, visit);
          currentFunction = prev;
        } else {
          ts.forEachChild(init, visit);
        }
      }
      return;
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
          callerName: currentFunction || GLOBAL_CALLER,
          calleeName,
          line: getLineOfPos(node.getStart(sourceFile)),
        });
      }
    }

    ts.forEachChild(node, visit);
    currentFunction = savedFunction;
    currentClass = savedClass;
  }

  visit(sourceFile);

  // Always include a synthetic (global) symbol so top-level call edges satisfy FK.
  if (!symbols.some((s) => s.name === GLOBAL_CALLER)) {
    symbols.push({
      name: GLOBAL_CALLER,
      kind: "Global",
      startLine: 1,
      endLine: 1,
      docstring: "",
      signature: "(global)",
    });
  }

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
  const selectSymbolsByFile = db.prepare("SELECT id, name FROM symbols WHERE file_path = ?");
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

  // Pass 1: hash first so unchanged workspaces can early-return without AST parse.
  interface ParsedFile {
    relPath: string;
    hash: string;
    size: number;
    content?: string;
    unchanged: boolean;
    symbols: {
      name: string;
      kind: string;
      startLine: number;
      endLine: number;
      docstring?: string;
      signature?: string;
    }[];
    calls: { callerName: string; calleeName: string; line: number }[];
    imports: { moduleName: string; localName: string; importedName: string }[];
  }
  const parsedAll: ParsedFile[] = [];
  // relPath -> (symbol name -> preferred id). Overloads keep the first declaration.
  const fileSymIds = new Map<string, Map<string, string>>();

  let anyChanged = force;
  for (const p of filePaths) {
    const relPath = toPosixRel(path.relative(absRoot, p));
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
    const existing = selectFile.get(relPath) as { hash: string } | undefined;
    const unchanged = !force && !!existing && existing.hash === hash;
    if (!unchanged) anyChanged = true;
    parsedAll.push({
      relPath,
      hash,
      size,
      content,
      unchanged,
      symbols: [],
      calls: [],
      imports: [],
    });
  }

  // Fast path: nothing on disk changed vs the ledger — skip AST work entirely.
  if (!anyChanged && parsedAll.length > 0) {
    const totalSymbols = (
      db.prepare("SELECT count(*) as count FROM symbols").get() as { count: number }
    ).count;
    const totalCalls = (
      db.prepare("SELECT count(*) as count FROM calls").get() as { count: number }
    ).count;
    return {
      totalFiles: parsedAll.length,
      updatedFiles: 0,
      skippedFiles: parsedAll.length,
      totalSymbols,
      totalCalls,
    };
  }

  // Pass 2: parse changed files; load symbol maps for unchanged from DB (for import resolution).
  for (const pf of parsedAll) {
    if (pf.unchanged) {
      const rows = selectSymbolsByFile.all(pf.relPath) as { id: string; name: string }[];
      const symMap = new Map<string, string>();
      for (const row of rows) {
        if (!symMap.has(row.name)) symMap.set(row.name, row.id);
      }
      fileSymIds.set(pf.relPath, symMap);
      // Still need AST for edge refresh when *other* files changed.
      try {
        const parsed = parseSourceFile(ts, pf.relPath, pf.content || "");
        pf.symbols = parsed.symbols;
        pf.calls = parsed.calls;
        pf.imports = parsed.imports;
      } catch {
        // keep empty; edge write will no-op
      }
      delete pf.content;
      continue;
    }

    try {
      const parsed = parseSourceFile(ts, pf.relPath, pf.content || "");
      pf.symbols = parsed.symbols;
      pf.calls = parsed.calls;
      pf.imports = parsed.imports;
    } catch {
      skippedFiles++;
      delete pf.content;
      continue;
    }
    delete pf.content;

    const symMap = new Map<string, string>();
    for (const sym of pf.symbols) {
      const symId = `${pf.relPath}:${sym.name}:${sym.kind}:${sym.startLine}`;
      if (!symMap.has(sym.name)) symMap.set(sym.name, symId);
    }
    fileSymIds.set(pf.relPath, symMap);
  }

  // Resolve a relative module specifier ("./fileB", "../x/y") to a known relPath.
  function resolveModule(importerRel: string, moduleName: string): string | null {
    if (!moduleName.startsWith(".")) return null;
    const dir = path.posix.dirname(importerRel);
    const base = path.posix.normalize(path.posix.join(dir, moduleName));
    const candidates = [
      base,
      `${base}.ts`,
      `${base}.tsx`,
      `${base}.js`,
      `${base}.jsx`,
      `${base}/index.ts`,
      `${base}/index.tsx`,
      `${base}/index.js`,
    ];
    for (const c of candidates) if (fileSymIds.has(c)) return c;
    return null;
  }

  // Write call/import edges using the current symbol-id map so cross-file
  // references stay valid even when only the callee file changed.
  function writeEdges(pf: (typeof parsedAll)[number]): void {
    deleteCalls.run(pf.relPath);
    deleteImports.run(pf.relPath);

    // local binding -> remote symbol id (resolve by *imported* export name)
    const importSym = new Map<string, string>();
    for (const imp of pf.imports) {
      const targetRel = resolveModule(pf.relPath, imp.moduleName);
      if (!targetRel) continue;
      const tid =
        fileSymIds.get(targetRel)?.get(imp.importedName) ??
        // default import often maps to a class/function with the local name in CJS/TS interop
        (imp.importedName === "default"
          ? fileSymIds.get(targetRel)?.get(imp.localName)
          : undefined);
      if (tid) importSym.set(imp.localName, tid);
    }

    const localSym = fileSymIds.get(pf.relPath);
    const globalId = localSym?.get(GLOBAL_CALLER) ?? `${pf.relPath}:${GLOBAL_CALLER}:Global:1`;

    // Ensure synthetic (global) symbol exists so top-level call edges satisfy FK
    // even when we only refresh edges for an unchanged file on an older DB.
    insertSymbol.run(globalId, pf.relPath, GLOBAL_CALLER, "Global", 1, 1, null, "(global)");
    localSym?.set(GLOBAL_CALLER, globalId);

    for (const call of pf.calls) {
      // Prefer the real symbol id; fall back to (global) so FK never fails.
      const callerId = localSym?.get(call.callerName) ?? globalId;
      // Prefer the imported symbol's id (cross-file, via local alias), then same-file,
      // else null (queries fall back to callee_name).
      const calleeId = importSym.get(call.calleeName) ?? localSym?.get(call.calleeName) ?? null;
      insertCall.run(callerId, call.calleeName, calleeId, pf.relPath, call.line);
    }

    for (const imp of pf.imports) {
      // Store local binding for display; resolution used importedName above.
      insertImport.run(pf.relPath, imp.moduleName, imp.localName);
    }
  }

  db.exec("BEGIN");
  try {
    for (const pf of parsedAll) {
      totalFiles++;
      const existing = selectFile.get(pf.relPath);
      if (!force && existing && existing.hash === pf.hash) {
        // File content unchanged — keep symbols, but re-resolve call edges so
        // they pick up symbol-id changes in imported modules.
        try {
          db.exec("SAVEPOINT file_edges");
          writeEdges(pf);
          db.exec("RELEASE file_edges");
        } catch {
          try {
            db.exec("ROLLBACK TO file_edges");
            db.exec("RELEASE file_edges");
          } catch {
            // ignore nested rollback failure
          }
        }
        skippedFiles++;
        continue;
      }

      try {
        updatedFiles++;
        db.exec("SAVEPOINT file_upsert");

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

        writeEdges(pf);
        db.exec("RELEASE file_upsert");
      } catch {
        // Roll back this file only; keep the outer transaction.
        try {
          db.exec("ROLLBACK TO file_upsert");
          db.exec("RELEASE file_upsert");
        } catch {
          // ignore
        }
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

// Throttle automatic reindex so rapid sequential queries don't re-walk the tree.
const ENSURE_INDEX_MIN_MS = 2_000;
const lastEnsureIndexAt = new Map<string, number>();

/**
 * Ensure the workspace index is warm. Runs a cheap incremental reindex
 * (hash-based skip of unchanged files), throttled so bursty tool calls
 * within ENSURE_INDEX_MIN_MS share one walk.
 */
async function ensureIndexed(workspace: string): Promise<DatabaseSync> {
  const abs = path.resolve(workspace);
  const db = await getDb(abs);
  const now = Date.now();
  const last = lastEnsureIndexAt.get(abs) ?? 0;
  if (now - last < ENSURE_INDEX_MIN_MS) {
    // Still reindex if the DB is empty (first query after wipe).
    const fileCount = (db.prepare("SELECT count(*) as count FROM files").get() as { count: number })
      .count;
    if (fileCount > 0) return db;
  }
  const ts = await getTs();
  await indexWorkspace(db, ts, abs, false);
  lastEnsureIndexAt.set(abs, Date.now());
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
    promptSnippet: "Build or refresh the codebase AST/SQLite index",
    promptGuidelines: [
      "Run CodebaseIndex to build or force-refresh the persistent AST/SQLite index before deep codebase analysis, or to pick up many new/changed files.",
      "The other Codebase* tools auto-index the workspace on first use, so you usually only need this for an explicit initial build or a forced full re-index.",
    ],
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
    promptSnippet: "Find symbols (functions/classes/types) by name or kind in the codebase",
    promptGuidelines: [
      "Use CodebaseFindSymbol whenever the user asks to locate, find, or search for a function, class, type, or any symbol by name or kind across the codebase.",
      "Prefer this over grep for codebase discovery or 'where is X defined' questions when you want structured matches with file/line and signatures; a kind filter (e.g. Function, Class) narrows results.",
    ],
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
    promptSnippet: "Get a symbol's declaration and source code",
    promptGuidelines: [
      "Use CodebaseGetDefinition to read the full declaration, signature, and source snippet of a specific symbol once you know its name.",
      "Prefer this over CodebaseFindSymbol when you already know the exact symbol name and want its implementation, not a list of candidates.",
    ],
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
    promptSnippet: "Find all callers/references to a symbol",
    promptGuidelines: [
      "Use CodebaseFindReferences to find every place that calls or references a symbol — essential for impact analysis, refactoring safety, and tracing how a function is used.",
      "Reach for this when the user asks 'who uses X', 'what calls X', or when assessing the blast radius of a change.",
    ],
    parameters: GetSymbolSchema,

    async execute(_id, params, _signal, _onUpdate, _ctx) {
      const workspace = (params.workspace as string) || process.cwd();
      const db = await ensureIndexed(workspace);
      const name = params.symbolName as string;

      const ids = (
        db.prepare("SELECT id FROM symbols WHERE name = ?").all(name) as { id: string }[]
      ).map((r) => r.id);
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
    promptSnippet: "Trace inbound/outbound call paths for a symbol",
    promptGuidelines: [
      "Use CodebaseGetCallGraph to visualize how a symbol is reached (inbound) or what it calls (outbound), up to a configurable depth.",
      "Use for architecture understanding, control-flow tracing, and mapping how data or control reaches a function through the call graph.",
    ],
    parameters: CallGraphSchema,

    async execute(_id, params, _signal, _onUpdate, _ctx) {
      const workspace = (params.workspace as string) || process.cwd();
      const db = await ensureIndexed(workspace);
      const startSym = params.symbolName as string;
      const direction = params.direction as "inbound" | "outbound";
      const depth = (params.depth as number | undefined) ?? 3;

      const lines: string[] = [`Call Graph for "${startSym}" (${direction}, max depth ${depth}):`];

      // Per-root visited set so multi-definition starts and diamond graphs keep alternate branches.
      function traceInbound(
        calleeId: string,
        calleeName: string,
        currentDepth: number,
        indent: string,
        visited: Set<string>,
      ) {
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
          traceInbound(c.caller_id, c.caller, currentDepth + 1, `${indent}  `, visited);
        }
      }

      function traceOutbound(
        callerId: string,
        callerName: string,
        currentDepth: number,
        indent: string,
        visited: Set<string>,
      ) {
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
          if (c.callee_id) {
            traceOutbound(c.callee_id, c.callee_name, currentDepth + 1, `${indent}  `, visited);
          } else {
            // Name-only edge: expand to all symbols with that name for multi-hop.
            const nexts = db
              .prepare("SELECT id, name FROM symbols WHERE name = ?")
              .all(c.callee_name) as { id: string; name: string }[];
            if (nexts.length === 0) {
              traceOutbound(c.callee_name, c.callee_name, currentDepth + 1, `${indent}  `, visited);
            } else {
              for (const n of nexts) {
                traceOutbound(n.id, n.name, currentDepth + 1, `${indent}  `, new Set(visited));
              }
            }
          }
        }
      }

      const startSyms = db.prepare("SELECT id, name FROM symbols WHERE name = ?").all(startSym) as {
        id: string;
        name: string;
      }[];
      if (startSyms.length === 0) {
        // Symbol not indexed: fall back to a name-only match so the trace still runs.
        if (direction === "inbound") traceInbound(startSym, startSym, 1, "  ", new Set());
        else traceOutbound(startSym, startSym, 1, "  ", new Set());
      } else if (direction === "inbound") {
        for (const s of startSyms) traceInbound(s.id, s.name, 1, "  ", new Set());
      } else {
        for (const s of startSyms) traceOutbound(s.id, s.name, 1, "  ", new Set());
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
    promptSnippet: "Trace call routes leading to a target symbol",
    promptGuidelines: [
      "Use CodebaseTraceCallPath to find concrete call chains that reach a target function — e.g. to prove a user-controlled input flows into a sensitive sink.",
      "Ideal for taint/flow analysis, exploit-chain construction, and proving reachability from an entry point to a vulnerable function; constrain the start with sourceSymbol to find only paths from a specific entry point.",
    ],
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

        // Exact match (case-insensitive). Substring matching caused false positives
        // like sourceFilter "run" matching "otherRun".
        if (sourceFilter && name.toLowerCase() === sourceFilter.toLowerCase()) {
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
    promptSnippet: "Summarize codebase layout, hotspot functions, and imports",
    promptGuidelines: [
      "Use CodebaseGetArchitecture for a high-level overview: directory structure, most-called (hotspot) functions, top imported modules, and corpus size.",
      "Reach for this whenever the user asks to 'analyze the codebase', understand the project structure, onboard to a repo, or find the most important/central functions.",
    ],
    parameters: WorkspaceSchema,

    async execute(_id, params, _signal, _onUpdate, _ctx) {
      const workspace = (params.workspace as string) || process.cwd();
      const db = await ensureIndexed(workspace);

      // Top Hotspot Functions (Highest Inbound Call Count).
      // Aggregate on callee first, then join a single representative symbol — joining
      // symbols by bare name before GROUP BY multiplies counts for common names.
      const hotspotStmt = db.prepare(`
        SELECT
          stats.callee_name,
          stats.call_count,
          s.file_path,
          s.kind
        FROM (
          SELECT
            COALESCE(callee_id, callee_name) as key,
            callee_name,
            count(*) as call_count
          FROM calls
          GROUP BY COALESCE(callee_id, callee_name)
          ORDER BY call_count DESC
          LIMIT 10
        ) stats
        LEFT JOIN symbols s ON s.id = stats.key OR (s.name = stats.callee_name AND stats.key = stats.callee_name)
        GROUP BY stats.key
        ORDER BY stats.call_count DESC
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
