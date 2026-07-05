/**
 * SQLite compatibility shim — transparently uses Node's built-in `node:sqlite`
 * (DatabaseSync) when available, falling back to Bun's `bun:sqlite` (Database).
 *
 * Duplicated from pi-casefile (which is published standalone and cannot export
 * shared internals). Keep the two copies in sync.
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
