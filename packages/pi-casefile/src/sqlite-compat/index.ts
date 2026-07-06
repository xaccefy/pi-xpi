import { createRequire } from "node:module";
const _require = createRequire(import.meta.url);

let DatabaseSync: any;
try {
  DatabaseSync = _require("bun:sqlite").Database as any;
} catch {
  DatabaseSync = (_require("node:sqlite") as any).DatabaseSync;
}

export { DatabaseSync };
