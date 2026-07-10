/**
 * pi-engage store — disk persistence for authenticated pentest sessions.
 *
 * Sessions are stored as JSON under `~/.pi/xpi-engage` (override with `PI_ENGAGE_DIR`),
 * which is outside the repo and git-ignored, so secrets never enter version control.
 * Session ids are sanitized to prevent path traversal.
 */

import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export type AuthMode = "cookie" | "oauth-client-credentials" | "mtls";

export interface AuthSession {
  id: string;
  label: string;
  target?: string;
  caseId?: string;
  mode: AuthMode;
  // cookie
  cookie?: string;
  // oauth client-credentials
  tokenUrl?: string;
  clientId?: string;
  clientSecret?: string;
  scope?: string;
  accessToken?: string;
  expiresAt?: number;
  // mtls
  certPath?: string;
  keyPath?: string;
  caPath?: string;
  createdAt: number;
  updatedAt: number;
}

function resolveEngageDir(): string {
  const fromEnv = process.env.PI_ENGAGE_DIR?.trim();
  if (fromEnv) return fromEnv;
  return join(homedir(), ".pi", "xpi-engage");
}

const ENGAGE_DIR = resolveEngageDir();

/** Reject path separators / traversal so session ids cannot escape ENGAGE_DIR. */
export function safeId(id: string): string {
  const cleaned = String(id ?? "")
    .replace(/[^a-zA-Z0-9._-]+/g, "_")
    .replace(/^\.+/, "")
    .slice(0, 128);
  return cleaned || "default";
}

function sessionPath(id: string): string {
  return join(ENGAGE_DIR, `${safeId(id)}.json`);
}

export function ensureDir(): void {
  if (!existsSync(ENGAGE_DIR)) mkdirSync(ENGAGE_DIR, { recursive: true });
}

export function saveSession(session: AuthSession): void {
  ensureDir();
  writeFileSync(sessionPath(session.id), JSON.stringify(session, null, 2), "utf8");
}

export function getSession(id: string): AuthSession | undefined {
  const p = sessionPath(id);
  if (!existsSync(p)) return undefined;
  try {
    return JSON.parse(readFileSync(p, "utf8")) as AuthSession;
  } catch {
    return undefined;
  }
}

export function listSessions(): AuthSession[] {
  if (!existsSync(ENGAGE_DIR)) return [];
  return readdirSync(ENGAGE_DIR)
    .filter((f) => f.endsWith(".json"))
    .map((f) => {
      try {
        return JSON.parse(readFileSync(join(ENGAGE_DIR, f), "utf8")) as AuthSession;
      } catch {
        return undefined;
      }
    })
    .filter((s): s is AuthSession => s !== undefined)
    .sort((a, b) => a.updatedAt - b.updatedAt);
}

export function deleteSession(id: string): boolean {
  const p = sessionPath(id);
  if (!existsSync(p)) return false;
  unlinkSync(p);
  return true;
}

export function clearSessions(): number {
  if (!existsSync(ENGAGE_DIR)) return 0;
  let n = 0;
  for (const f of readdirSync(ENGAGE_DIR)) {
    if (f.endsWith(".json")) {
      unlinkSync(join(ENGAGE_DIR, f));
      n++;
    }
  }
  return n;
}
