// ponytail: thin re-export with any cast to match node:sqlite API
import { Database } from "bun:sqlite";
const instance = Database as any;
export { instance as DatabaseSync };
export type DatabaseSync = any;
