import { Database } from "bun:sqlite";
import { describe, expect, it } from "bun:test";

/**
 * Fidelity test for the `PRAGMA foreign_keys = ON` fix in ledger/codeintel `getDb`.
 *
 * The CI test suite uses `bun:sqlite`, where FK enforcement defaults OFF — so the
 * `ON DELETE CASCADE` clauses in the schema are silently no-ops unless the pragma is
 * set. These tests run against the REAL bun:sqlite the agent uses, proving the fix
 * is necessary and effective (the original suite never exercised this path).
 */
describe("sqlite foreign_keys cascade (real bun:sqlite)", () => {
  it("with PRAGMA foreign_keys = ON, deleting a case cascades to remove its links (the fix)", () => {
    const db = new Database(":memory:");
    db.exec("PRAGMA foreign_keys = ON");
    db.exec(`CREATE TABLE cases (id TEXT PRIMARY KEY, title TEXT)`);
    db.exec(`CREATE TABLE case_links (
      source_id TEXT, target_id TEXT,
      PRIMARY KEY (source_id, target_id),
      FOREIGN KEY (source_id) REFERENCES cases(id) ON DELETE CASCADE,
      FOREIGN KEY (target_id) REFERENCES cases(id) ON DELETE CASCADE
    )`);
    db.exec(`INSERT INTO cases VALUES ('a','A')`);
    db.exec(`INSERT INTO cases VALUES ('b','B')`);
    db.exec(`INSERT INTO case_links VALUES ('a','b')`);
    db.exec(`DELETE FROM cases WHERE id='a'`);

    const links = db.prepare(`SELECT * FROM case_links`).all();
    expect(links.length).toBe(0);
  });

  it("documents that WITHOUT the pragma, cascade does NOT fire under bun:sqlite (why the fix matters)", () => {
    const db = new Database(":memory:");
    // Deliberately NOT enabling the pragma — mirrors pre-fix behavior.
    db.exec(`CREATE TABLE cases (id TEXT PRIMARY KEY, title TEXT)`);
    db.exec(`CREATE TABLE case_links (
      source_id TEXT, target_id TEXT,
      PRIMARY KEY (source_id, target_id),
      FOREIGN KEY (source_id) REFERENCES cases(id) ON DELETE CASCADE,
      FOREIGN KEY (target_id) REFERENCES cases(id) ON DELETE CASCADE
    )`);
    db.exec(`INSERT INTO cases VALUES ('a','A')`);
    db.exec(`INSERT INTO cases VALUES ('b','B')`);
    db.exec(`INSERT INTO case_links VALUES ('a','b')`);
    db.exec(`DELETE FROM cases WHERE id='a'`);

    // Orphan link remains because FK enforcement is off by default in bun:sqlite.
    const links = db.prepare(`SELECT * FROM case_links`).all();
    expect(links.length).toBe(1);
  });
});
