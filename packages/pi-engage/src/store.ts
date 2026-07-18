/**
 * pi-engage store — disk persistence for authenticated pentest sessions.
 *
 * Sessions are stored as JSON under `~/.pi/xpi-engage` (override with `PI_ENGAGE_DIR`),
 * which is outside the repo and git-ignored, so secrets never enter version control.
 * Session ids are sanitized to prevent path traversal.
 */

import {
  chmodSync,
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

// Resolved lazily on every call so tests can redirect via PI_ENGAGE_DIR — a
// module-level constant baked the path in at import time and made tests touch
// the real ~/.pi/xpi-engage (clearSessions wiped actual sessions).
function engageDir(): string {
  return resolveEngageDir();
}

/** Reject path separators / traversal so session ids cannot escape the engage dir. */
export function safeId(id: string): string {
  const cleaned = String(id ?? "")
    .replace(/[^a-zA-Z0-9._-]+/g, "_")
    .replace(/^\.+/, "")
    .slice(0, 128);
  return cleaned || "default";
}

function sessionPath(id: string): string {
  return join(engageDir(), `${safeId(id)}.json`);
}

export function ensureDir(): void {
  const dir = engageDir();
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true, mode: 0o700 });
  // Harden pre-existing dirs created before perms were enforced.
  try {
    chmodSync(dir, 0o700);
  } catch {
    /* best-effort */
  }
}

export function saveSession(session: AuthSession): void {
  ensureDir();
  const p = sessionPath(session.id);
  // Sessions hold cookies / client secrets / tokens — never world-readable.
  writeFileSync(p, JSON.stringify(session, null, 2), { encoding: "utf8", mode: 0o600 });
  try {
    chmodSync(p, 0o600); // mode only applies on creation; harden rewrites too
  } catch {
    /* best-effort */
  }
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
  const dir = engageDir();
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((f) => f.endsWith(".json"))
    .map((f) => {
      try {
        return JSON.parse(readFileSync(join(dir, f), "utf8")) as AuthSession;
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
  const dir = engageDir();
  if (!existsSync(dir)) return 0;
  let n = 0;
  for (const f of readdirSync(dir)) {
    if (f.endsWith(".json")) {
      unlinkSync(join(dir, f));
      n++;
    }
  }
  return n;
}
