/**
 * SQLite compatibility shim — transparently uses Node's built-in `node:sqlite`
 * (DatabaseSync) when available, falling back to Bun's `bun:sqlite` (Database).
 *
 * This file is intentionally duplicated in pi-codeintel because pi-casefile is
 * published as a standalone npm package and cannot share an internal module
 * with sibling workspace packages. Keep the two copies in sync.
 */

/** A prepared SQL statement (subset of the API used by XPI). */
export interface StatementSync {
  run(...params: unknown[]): { changes: number | bigint; lastInsertRowid: number | bigint };
  get(...params: unknown[]): any;
  all(...params: unknown[]): any[];
}

/** A synchronous SQLite database connection (subset of the API used by XPI). */
export interface DatabaseSync {
  exec(sql: string): void;
  prepare(sql: string): StatementSync;
  close?(): void;
}

/** Constructor loaded at module init — instance type is the `DatabaseSync` interface above. */
export let DatabaseSync: new (path: string) => DatabaseSync;

try {
  const mod = await import("node:sqlite");
  DatabaseSync = mod.DatabaseSync;
} catch {
  const mod = await import("bun:sqlite");
  DatabaseSync = mod.Database;
}
