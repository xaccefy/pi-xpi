import { createRequire } from "node:module";

const _require = createRequire(import.meta.url);

// biome-ignore lint/suspicious/noExplicitAny: Runtime module swappability requires any casting
let DatabaseSyncConstructor: any;
try {
  // biome-ignore lint/suspicious/noExplicitAny: Runtime module swappability
  DatabaseSyncConstructor = _require("bun:sqlite").Database as any;
} catch {
  // biome-ignore lint/suspicious/noExplicitAny: Runtime module swappability
  DatabaseSyncConstructor = (_require("node:sqlite") as any).DatabaseSync;
}

// biome-ignore lint/suspicious/noExplicitAny: Standard SQLite API returns any
export interface StatementSync {
  run(...args: unknown[]): { lastInsertRowid: number; changes: number };
  // biome-ignore lint/suspicious/noExplicitAny: Standard SQLite API returns any
  get(...args: unknown[]): any;
  // biome-ignore lint/suspicious/noExplicitAny: Standard SQLite API returns any
  all(...args: unknown[]): any[];
}

export interface DatabaseSync {
  prepare(sql: string): StatementSync;
  exec(sql: string): void;
  close(): void;
}

export const DatabaseSync: new (path: string) => DatabaseSync = DatabaseSyncConstructor;
