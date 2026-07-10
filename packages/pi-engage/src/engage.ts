import { type ChildProcess, spawn } from "node:child_process";
import { resolveSessionRequest } from "./credential.ts";
import type { AuthMode } from "./store.ts";
import * as store from "./store.ts";
import type { AuthSession, EngageAction, FetchImpl, Finding, FindingSeverity } from "./types.ts";

export interface OpResult {
  text: string;
  isError?: boolean;
  details?: unknown;
}

export interface ExecResult {
  code: number;
  stdout: string;
  stderr: string;
}

export interface EngageDeps {
  /** Inject a fake executor (tests). Defaults to a real child_process.spawn. */
  execImpl?: (tool: string, args: string[]) => Promise<ExecResult>;
  /** Inject a fake fetch (tests). Defaults to global fetch. */
  fetchImpl?: FetchImpl;
  now?: () => number;
}

const MASK = "***";
const BASE_SECURITY_HEADERS = [
  "content-security-policy",
  "strict-transport-security",
  "x-frame-options",
  "x-content-type-options",
];

/** Tools that take a positional URL (curl) vs `-u` (nuclei/httpx/ffuf/...). */
const POSITIONAL_URL_TOOLS = new Set(["curl"]);

function ok(text: string, details?: unknown): OpResult {
  return { text, details };
}
function err(text: string, details?: unknown): OpResult {
  return { text, details, isError: true };
}

function maskSession(s: AuthSession): AuthSession {
  return {
    ...s,
    cookie: s.cookie ? MASK : undefined,
    clientSecret: s.clientSecret ? MASK : undefined,
    accessToken: s.accessToken ? MASK : undefined,
  };
}

/** Turn resolved auth headers (and mTLS files) into CLI flags for pdtm tools. */
export function headersToFlags(
  headers: Record<string, string>,
  mode: AuthMode,
  session?: AuthSession,
): string[] {
  const flags: string[] = [];
  for (const [k, v] of Object.entries(headers)) flags.push("-H", `${k}: ${v}`);
  if (mode === "mtls" && session) {
    if (session.certPath) flags.push("--cert", session.certPath);
    if (session.keyPath) flags.push("--key", session.keyPath);
    if (session.caPath) flags.push("--cacert", session.caPath);
  }
  return flags;
}

/** Assemble the argv for a pdtm tool, auth flags first, then target, then extras. */
export function buildToolArgs(
  tool: string,
  target: string | undefined,
  authFlags: string[],
  extra: string[],
): string[] {
  const head = POSITIONAL_URL_TOOLS.has(tool)
    ? [...authFlags, ...(target ? [target] : [])]
    : [...authFlags, ...(target ? ["-u", target] : [])];
  return [...head, ...extra];
}

/** Parse nuclei JSONL output into findings (no-op for other tools). */
export function parseToolOutput(tool: string, stdout: string): Omit<Finding, "foundAt" | "id">[] {
  if (tool !== "nuclei") return [];
  const out: Omit<Finding, "foundAt" | "id">[] = [];
  for (const line of stdout.split("\n")) {
    const t = line.trim();
    if (!t) continue;
    try {
      const j = JSON.parse(t) as {
        template?: string;
        severity?: string;
        host?: string;
        "matched-at"?: string;
      };
      if (j && (j.severity || j["matched-at"] || j.template)) {
        out.push({
          url: j["matched-at"] || j.host || "",
          type: j.template || "nuclei",
          severity: (j.severity as FindingSeverity) || "info",
          detail: j.template || "nuclei issue",
          evidence: t,
        });
      }
    } catch {
      /* not a JSON line */
    }
  }
  return out;
}

/**
 * Session manager + pdtm-tool bridge. The agent holds a sanctioned session and
 * drives real pentest CLIs (curl / nuclei / httpx / ffuf / ...) with the auth
 * injected — no MITM proxy needed.
 */
export class Engage {
  private lastSessionId?: string;

  constructor(private deps: EngageDeps = {}) {}

  private get fetchImpl(): FetchImpl {
    return this.deps.fetchImpl ?? fetch;
  }
  private get now(): number {
    return this.deps.now ? this.deps.now() : Date.now();
  }
  private exec(tool: string, args: string[]): Promise<ExecResult> {
    return this.deps.execImpl ? this.deps.execImpl(tool, args) : this.realExec(tool, args);
  }

  private realExec(tool: string, args: string[]): Promise<ExecResult> {
    const proc: ChildProcess = spawn(tool, args, {});
    return new Promise((resolve) => {
      let stdout = "";
      let stderr = "";
      const timer = setTimeout(() => {
        try {
          proc.kill("SIGKILL");
        } catch {
          /* already gone */
        }
        resolve({ code: -1, stdout, stderr: `${stderr}\n[engage] exec timed out` });
      }, 120_000);
      proc.stdout?.on("data", (d) => {
        stdout += d.toString();
      });
      proc.stderr?.on("data", (d) => {
        stderr += d.toString();
      });
      proc.on("close", (code) => {
        clearTimeout(timer);
        resolve({ code: code ?? -1, stdout, stderr });
      });
      proc.on("error", (e) => {
        clearTimeout(timer);
        resolve({
          code: -1,
          stdout,
          stderr: `${stderr}\n${e instanceof Error ? e.message : String(e)}`,
        });
      });
    });
  }

  // ---- session management ------------------------------------------------
  addSession(input: EngageSetupInput): OpResult {
    if (!input.id) return err("id is required for add");
    if (!input.mode)
      return err("mode is required for add (cookie | oauth-client-credentials | mtls)");
    const session: AuthSession = {
      ...(input as AuthSession),
      createdAt: this.now,
      updatedAt: this.now,
    };
    store.saveSession(session);
    this.lastSessionId = session.id;
    return ok(`Saved session ${session.id} (${session.mode})`, {
      id: session.id,
      mode: session.mode,
    });
  }

  getSession(id: string): OpResult {
    const s = store.getSession(id);
    if (!s) return err(`session ${id} not found`);
    return ok(`Session ${id}`, { session: maskSession(s) });
  }

  listSessions(): OpResult {
    const all = store.listSessions().map(maskSession);
    return ok(`Listing ${all.length} session(s)`, { sessions: all });
  }

  async token(id: string): Promise<OpResult> {
    const s = store.getSession(id);
    if (!s) return err(`session ${id} not found`);
    const r = await resolveSessionRequest(s, this.fetchImpl);
    this.lastSessionId = id;
    return ok(`Resolved auth for ${id}`, r);
  }

  deleteSession(id: string): OpResult {
    return store.deleteSession(id)
      ? ok(`Deleted session ${id}`, { id, deleted: true })
      : err(`session ${id} not found`);
  }

  clearSessions(): OpResult {
    const n = store.clearSessions();
    return ok(`Cleared ${n} session(s)`, { cleared: n });
  }

  // ---- pdtm tool bridge --------------------------------------------------
  async run(input: EngageRunInput): Promise<OpResult> {
    if (!input.tool) return err("run requires `tool` (e.g. nuclei, httpx, ffuf, curl, whatweb)");
    const sid = input.sessionId ?? this.lastSessionId;
    let authFlags: string[] = [];
    if (sid) {
      const s = store.getSession(sid);
      if (!s) return err(`session ${sid} not found`);
      const r = await resolveSessionRequest(s, this.fetchImpl);
      const headers: Record<string, string> = { ...r.headers };
      if (s.cookie) headers.Cookie = s.cookie;
      authFlags = headersToFlags(headers, s.mode, s);
      this.lastSessionId = sid;
    }
    const args = buildToolArgs(input.tool, input.url, authFlags, input.args ?? []);
    const result = await this.exec(input.tool, args);
    const parsed = parseToolOutput(input.tool, result.stdout);
    return ok(`Ran ${input.tool} (exit ${result.code})`, {
      command: `${input.tool} ${args.map((a) => (a.includes(" ") ? JSON.stringify(a) : a)).join(" ")}`,
      exitCode: result.code,
      stderr: result.stderr.slice(0, 1000),
      stdoutSnippet: result.stdout.slice(0, 3000),
      findings: parsed,
    });
  }

  // ---- single authenticated request -------------------------------------
  async send(input: EngageSendInput): Promise<OpResult> {
    const sid = input.sessionId ?? this.lastSessionId;
    if (!sid) return err("send requires sessionId (or run setup first)");
    const s = store.getSession(sid);
    if (!s) return err(`session ${sid} not found`);
    if (!input.url) return err("send requires url");
    const auth = await resolveSessionRequest(s, this.fetchImpl);
    const headers: Record<string, string> = { ...auth.headers, ...(input.headers ?? {}) };
    if (s.cookie && !headers.Cookie) headers.Cookie = s.cookie;
    const method = input.method ?? "GET";
    const res = await this.fetchImpl(input.url, { method, headers, body: input.body });
    const text = await res.text();
    const curl =
      `curl -X ${method} '${input.url}'` +
      Object.entries(headers)
        .map(([k, v]) => ` -H '${k}: ${v}'`)
        .join("");
    return ok(`[${res.status}] ${input.url}`, {
      status: res.status,
      responseHeaders: Object.fromEntries(res.headers),
      snippet: text.slice(0, 2000),
      authHeaders: auth.headers,
      curl,
    });
  }

  // ---- discovery ---------------------------------------------------------
  async spider(input: EngageSpiderInput): Promise<OpResult> {
    const sid = input.sessionId ?? this.lastSessionId;
    if (!sid) return err("spider requires sessionId (or run setup first)");
    const s = store.getSession(sid);
    if (!s) return err(`session ${sid} not found`);
    if (!input.url) return err("spider requires url");
    const auth = await resolveSessionRequest(s, this.fetchImpl);
    const base = new URL(input.url);
    const visited = new Set<string>();
    const queue: string[] = [input.url];
    const inScope = input.inScope ?? [base.host];
    const maxDepth = input.depth ?? 2;
    let count = 0;
    let guard = 0;
    while (queue.length && visited.size < 200 && guard < maxDepth * 50) {
      guard++;
      const u = queue.shift() as string;
      if (visited.has(u)) continue;
      visited.add(u);
      try {
        const res = await this.fetchImpl(u, { headers: auth.headers });
        const html = await res.text();
        count++;
        const links = extractLinks(html, base);
        for (const l of links) {
          try {
            const abs = new URL(l, base);
            if (
              inScope.some((h) => abs.host === h || abs.host.endsWith(`.${h}`)) &&
              !visited.has(abs.href)
            ) {
              queue.push(abs.href);
            }
          } catch {
            /* ignore */
          }
        }
      } catch {
        /* out-of-scope / unreachable — skipped */
      }
    }
    return ok(`Spider visited ${count} in-scope URL(s)`, {
      visited: [...visited],
    });
  }

  // ---- scan --------------------------------------------------------------
  async scan(input: EngageScanInput): Promise<OpResult> {
    const sid = input.sessionId ?? this.lastSessionId;
    if (!input.url) return err("scan requires url");
    // If nuclei is installed, run it authenticated (the real pdtm scan path).
    const probe = await this.exec("nuclei", ["-version"]);
    if (probe.code === 0) {
      return this.run({
        tool: "nuclei",
        url: input.url,
        sessionId: sid,
        args: ["-silent", "-json"],
      });
    }
    // Passive fallback: fetch + inspect baseline security headers.
    const s = sid ? store.getSession(sid) : undefined;
    const headers = s ? (await resolveSessionRequest(s, this.fetchImpl)).headers : {};
    const res = await this.fetchImpl(input.url, { headers });
    const h = Object.fromEntries(res.headers);
    const missing = BASE_SECURITY_HEADERS.filter((k) => !h[k]);
    return ok(
      `Passive scan of ${input.url}: ${missing.length ? "issues found" : "clean"} (nuclei not found — install pdtm for active scan)`,
      { missing, responseHeaders: h },
    );
  }
}

function extractLinks(html: string, base: URL): string[] {
  const out: string[] = [];
  const re = /href\s*=\s*["']([^"']+)["']|src\s*=\s*["']([^"']+)["']/gi;
  let m = re.exec(html);
  while (m) {
    const raw = m[1] ?? m[2];
    if (
      raw &&
      !raw.startsWith("#") &&
      !raw.startsWith("mailto:") &&
      !raw.startsWith("javascript:")
    ) {
      try {
        out.push(new URL(raw, base).href);
      } catch {
        /* ignore malformed */
      }
    }
    m = re.exec(html);
  }
  return out;
}

// ---- input shapes --------------------------------------------------------
export interface EngageSetupInput {
  sessionId?: string;
  id?: string;
  label?: string;
  caseId?: string;
  target?: string;
  targetHost?: string;
  mode?: AuthMode;
  cookie?: string;
  tokenUrl?: string;
  clientId?: string;
  clientSecret?: string;
  scope?: string;
  certPath?: string;
  keyPath?: string;
  caPath?: string;
}

export interface EngageRunInput {
  tool?: string;
  url?: string;
  sessionId?: string;
  args?: string[];
}

export interface EngageSendInput {
  url?: string;
  sessionId?: string;
  method?: string;
  body?: string;
  headers?: Record<string, string>;
}

export interface EngageSpiderInput {
  url?: string;
  sessionId?: string;
  inScope?: string[];
  depth?: number;
}

export interface EngageScanInput {
  url?: string;
  sessionId?: string;
}

export type { AuthSession, EngageAction };
