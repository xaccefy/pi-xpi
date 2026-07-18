import { type ChildProcess, spawn } from "node:child_process";
import { resolveSessionRequest } from "./credential.ts";
import { DisposableInbox } from "./inbox.ts";
import type { AuthMode } from "./store.ts";
import * as store from "./store.ts";
import type { AuthSession, FetchImpl } from "./types.ts";

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

/** Tools that take a positional URL (curl) vs `-u` (httpx/ffuf/...). */
const POSITIONAL_URL_TOOLS = new Set(["curl"]);
/** Curated, fast, auth-injectable CLI set (all accept -H headers + -u target). nuclei dropped: too slow; subfinder/whatweb use non--u targets. */
const SUPPORTED_TOOLS = new Set(["curl", "httpx", "ffuf"]);
const REQUEST_TIMEOUT_MS = 30_000;

/**
 * Detect an application-level registration failure. HTTP errors are obvious;
 * the subtle case is HTTP 200 with an error payload, which several APIs use
 * (SOA2-style `{ Ack, Errors }`, or `{ success:false }` / `{ error }`). Returning
 * a reason here prevents the tool from reporting a false "Signed up" when the
 * target actually rejected the request.
 */
function signupRejected(body: string, httpOk: boolean): string | undefined {
  if (!httpOk) return "HTTP error";
  try {
    const j = JSON.parse(body) as Record<string, unknown>;
    const rs = j.ResponseStatus as { Ack?: string; Errors?: unknown[] } | undefined;
    if (rs) {
      if (Array.isArray(rs.Errors) && rs.Errors.length > 0) {
        return rs.Errors.map((e) => {
          const o = e as Record<string, unknown>;
          return String(o.Message ?? o.Description ?? o.message ?? JSON.stringify(e));
        }).join("; ");
      }
      if (rs.Ack && rs.Ack !== "Success") return `Ack=${rs.Ack}`;
    }
    if (j.success === false) {
      return String((j.message as string) ?? (j.error as string) ?? "success=false");
    }
    if (typeof j.error === "string" && j.error) return j.error;
    if (j.errorCode) return String(j.errorCode);
  } catch {
    /* not JSON — treat as accepted */
  }
  return undefined;
}

/** Escape a string for a POSIX single-quoted shell context (copy-paste curl commands). */
function shellSingleQuote(s: string): string {
  return `'${s.replace(/'/g, "'\\''")}'`;
}

/** Conditionally quote for shell display — only when the arg contains special chars. */
function shellQuote(s: string): string {
  if (s === "") return "''";
  if (/^[a-zA-Z0-9_@%+=:,./-]+$/.test(s)) return s;
  return `'${s.replace(/'/g, "'\\''")}'`;
}

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

/** Validate that mode-specific fields are present (catch silent auth failures early). */
function validateSessionFields(input: EngageSetupInput): string | undefined {
  switch (input.mode) {
    case "cookie":
      if (!input.cookie?.trim()) return "cookie mode requires a cookie value";
      break;
    case "oauth-client-credentials":
      if (!input.tokenUrl?.trim()) return "oauth-client-credentials requires tokenUrl";
      if (!input.clientId?.trim()) return "oauth-client-credentials requires clientId";
      if (!input.clientSecret?.trim()) return "oauth-client-credentials requires clientSecret";
      break;
    case "mtls":
      if (!input.certPath?.trim()) return "mtls requires certPath";
      if (!input.keyPath?.trim()) return "mtls requires keyPath";
      break;
  }
  return undefined;
}

// parseToolOutput removed: nuclei (its only consumer) was dropped as too slow.

/**
 * Session manager + pdtm-tool bridge. The agent holds a sanctioned session and
 * drives curated pentest CLIs (curl / httpx / ffuf) with the auth
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
    const modeErr = validateSessionFields(input);
    if (modeErr) return err(modeErr);
    // Strip sessionId — a routing field, not part of the stored session.
    const { sessionId: _sid, ...rest } = input;
    const session: AuthSession = {
      ...(rest as AuthSession),
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
    if (!input.tool) return err("run requires `tool`");
    if (!SUPPORTED_TOOLS.has(input.tool))
      return err(
        `unsupported tool '${input.tool}'; use one of: ${[...SUPPORTED_TOOLS].join(", ")}`,
      );
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
    return ok(`Ran ${input.tool} (exit ${result.code})`, {
      command: `${input.tool} ${args.map(shellQuote).join(" ")}`,
      exitCode: result.code,
      stderr: result.stderr.slice(0, 1000),
      stdoutSnippet: result.stdout.slice(0, 3000),
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
    const res = await this.fetchImpl(input.url, {
      method,
      headers,
      body: input.body,
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    const text = await res.text();
    const curlParts = [`curl -X ${method}`, shellSingleQuote(input.url)];
    for (const [k, v] of Object.entries(headers)) {
      curlParts.push("-H", shellSingleQuote(`${k}: ${v}`));
    }
    if (input.body) curlParts.push("-d", shellSingleQuote(input.body));
    const curl = curlParts.join(" ");
    return ok(`[${res.status}] ${input.url}`, {
      status: res.status,
      responseHeaders: Object.fromEntries(res.headers),
      snippet: text.slice(0, 2000),
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
    const inScope = input.inScope ?? [base.host];
    const maxDepth = input.depth ?? 2;
    const queue: { url: string; depth: number }[] = [{ url: input.url, depth: 0 }];
    let count = 0;
    while (queue.length && visited.size < 200) {
      const item = queue.shift();
      if (!item) break;
      const { url: u, depth } = item;
      if (visited.has(u)) continue;
      visited.add(u);
      try {
        const res = await this.fetchImpl(u, {
          headers: auth.headers,
          signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
        });
        const html = await res.text();
        count++;
        // Resolve relative links against the page they were found on, not the
        // seed URL — otherwise nested pages produce wrong absolute URLs.
        const links = extractLinks(html, new URL(u));
        for (const l of links) {
          try {
            const abs = new URL(l, base);
            if (
              depth + 1 <= maxDepth &&
              inScope.some((h) => abs.host === h || abs.host.endsWith(`.${h}`)) &&
              !visited.has(abs.href)
            ) {
              queue.push({ url: abs.href, depth: depth + 1 });
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

  // ---- account self-registration (autonomous low-priv seat) ----------
  async signup(input: EngageSignupInput): Promise<OpResult> {
    if (!input.signupUrl) return err("signup requires signupUrl");
    const strategy = input.verifyStrategy ?? "auto";

    // Own an inbox up front when verification may need one.
    let inbox: DisposableInbox | undefined;
    if (strategy === "auto" || strategy === "inbox") {
      try {
        inbox = await DisposableInbox.create(this.fetchImpl);
      } catch (e) {
        if (strategy === "inbox") {
          return err(`inbox creation failed: ${(e as Error).message}`);
        }
        // auto: fall through to response/none strategies
      }
    }

    const user = crypto.randomUUID().replace(/-/g, "");
    const pass = crypto.randomUUID().replace(/-/g, "");
    const email = inbox?.address ?? `${user}@${input.target ?? "example.com"}`;

    // Substitute placeholders in the supplied field map.
    const fields: Record<string, string> = {};
    for (const [k, v] of Object.entries(input.signupFields ?? {})) {
      fields[k] = v
        .replace(/<EMAIL>/g, email)
        .replace(/<USER>/g, user)
        .replace(/<PASS>/g, pass);
    }
    if (Object.keys(fields).length === 0) {
      fields.email = email;
      fields.password = pass;
      fields.username = user;
    }

    const signupRes = await this.fetchImpl(input.signupUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(fields),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    const signupBody = await signupRes.text();

    // Reject early if the target declined the registration — HTTP error OR an
    // application-level error in the body. Many APIs return HTTP 200 with an
    // error payload (e.g. `{ Ack: "Failure", Errors: [...] }`), so trusting the
    // status alone produces false "Signed up" results. No session is stored.
    const rejectReason = signupRejected(signupBody, signupRes.ok);
    if (rejectReason) {
      return err(`signup rejected by target: ${rejectReason}`, {
        registered: false,
        reason: rejectReason,
        body: signupBody.slice(0, 500),
      });
    }
    const session = this.captureSession(signupRes, signupBody, {
      id: input.sessionId ?? `signup-${user}`,
      label: input.label ?? "auto-signup",
      target: input.target,
      caseId: input.caseId,
    });
    store.saveSession(session);
    this.lastSessionId = session.id;

    // Verify the account (strategy-dependent).
    let verified: string | undefined;
    if (strategy !== "none") {
      // 1) verification token leaked in the signup response body
      const leaked = DisposableInbox.extractVerificationLink({
        text: signupBody,
        html: signupBody,
      });
      if (leaked && (strategy === "auto" || strategy === "response")) {
        await this.fetchImpl(leaked, { signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
        verified = leaked;
      }
      // 2) verification link delivered to the disposable inbox
      if (!verified && inbox) {
        const msg = await inbox.waitForMessage(
          (m) => (m.text ?? "").includes(email) || /verif|confirm/i.test(m.subject ?? ""),
          input.verifyTimeoutMs ?? 90_000,
        );
        const link = msg ? DisposableInbox.extractVerificationLink(msg) : undefined;
        if (link) {
          await this.fetchImpl(link, { signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
          verified = link;
        }
      }
    }

    const registered = true;
    // Prove the account exists: either email verification completed, or we
    // logged in with the same credentials. A registered-but-unverified,
    // unlogged-in account is "unconfirmed" — we cannot prove it actually exists.
    // When strategy is 'none' AND no login was attempted we intentionally skip
    // verification, so we treat it as confirmed; if a loginUrl was supplied the
    // login result is the proof and a failed login means unconfirmed.
    const loginUrl = input.loginUrl;
    let loginConfirmed: boolean | undefined;
    if (loginUrl) {
      const lr = await this.attemptLogin(
        loginUrl,
        input.loginFields,
        input.target,
        input.label ?? "auto-login",
        input.caseId,
        session.id,
        user,
        pass,
        email,
      );
      loginConfirmed = lr.ok;
    }
    const accountConfirmed =
      !!verified || !!loginConfirmed || (strategy === "none" && !loginUrl ? registered : false);

    return ok(
      `Signed up ${email} (session ${session.id})` +
        (verified
          ? ", verified (email)"
          : loginConfirmed
            ? ", account confirmed via login"
            : loginUrl
              ? ", UNVERIFIED — login rejected (account likely not created)"
              : strategy === "none"
                ? ", unverified (verification skipped)"
                : ", UNVERIFIED — account existence unconfirmed"),
      {
        sessionId: session.id,
        email,
        mode: session.mode,
        registered,
        verified: !!verified,
        loginConfirmed: !!loginConfirmed,
        accountConfirmed,
      },
    );
  }

  async login(input: EngageLoginInput): Promise<OpResult> {
    if (!input.loginUrl) return err("login requires loginUrl");
    const r = await this.attemptLogin(
      input.loginUrl,
      input.loginFields,
      input.target,
      input.label,
      input.caseId,
      input.sessionId,
    );
    if (!r.ok) {
      return err(`login failed: ${r.reason}`, { loggedIn: false, reason: r.reason });
    }
    if (!r.session) {
      return ok(
        `Logged in to ${input.target ?? input.loginUrl} (accepted, no session material returned)`,
        {
          loggedIn: true,
        },
      );
    }
    return ok(`Logged in to ${input.target ?? input.loginUrl} (session ${r.session.id})`, {
      sessionId: r.session.id,
      mode: r.session.mode,
      loggedIn: true,
    });
  }

  /**
   * Build an AuthSession from a response's cookie or JSON token. Always returns a
   * session (cookie mode when a cookie is present, else oauth mode which may
   * carry no token). Callers decide whether to store it.
   */
  private captureSession(
    res: Response,
    body: string,
    opts: { id: string; label: string; target?: string; caseId?: string },
  ): AuthSession {
    const sc = (res.headers as { getSetCookie?: () => string[] }).getSetCookie?.() ?? [];
    // Combine ALL Set-Cookie pairs into one Cookie header. Taking only the first
    // cookie breaks apps that set a tracking cookie before the session cookie.
    const cookie =
      sc.length > 0
        ? sc.map((c) => c.split(";")[0]).join("; ")
        : res.headers.get("set-cookie")?.split(";")[0];
    let tok: string | undefined;
    try {
      const j = JSON.parse(body) as Record<string, unknown>;
      tok = (j.token ?? j.access_token ?? j.accessToken) as string | undefined;
    } catch {
      /* not JSON */
    }
    return cookie
      ? {
          id: opts.id,
          label: opts.label,
          target: opts.target,
          caseId: opts.caseId,
          mode: "cookie",
          cookie,
          createdAt: this.now,
          updatedAt: this.now,
        }
      : {
          id: opts.id,
          label: opts.label,
          target: opts.target,
          caseId: opts.caseId,
          mode: "oauth-client-credentials",
          accessToken: tok,
          expiresAt: tok ? this.now + 3_600_000 : undefined,
          createdAt: this.now,
          updatedAt: this.now,
        };
  }

  /**
   * Attempt a login with the given credentials and capture the resulting session.
   * Returns ok:false (with a reason) when the target rejects the login at the
   * HTTP or application level — this is the proof that an account does/doesn't
   * exist for the supplied credentials.
   */
  private async attemptLogin(
    loginUrl: string,
    fields: Record<string, string> | undefined,
    target?: string,
    label?: string,
    caseId?: string,
    sessionId?: string,
    user: string = crypto.randomUUID().replace(/-/g, ""),
    pass: string = crypto.randomUUID().replace(/-/g, ""),
    email?: string,
  ): Promise<{ ok: boolean; session?: AuthSession; reason?: string }> {
    const f: Record<string, string> = {};
    for (const [k, v] of Object.entries(fields ?? { email: "<EMAIL>", password: "<PASS>" })) {
      f[k] = v
        .replace(/<EMAIL>/g, email ?? `${user}@${target ?? "example.com"}`)
        .replace(/<USER>/g, user)
        .replace(/<PASS>/g, pass);
    }
    let res: Response;
    try {
      res = await this.fetchImpl(loginUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(f),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
    } catch (e) {
      return { ok: false, reason: `request error: ${(e as Error).message}` };
    }
    const body = await res.text();
    const reason = signupRejected(body, res.ok);
    if (reason) return { ok: false, reason };
    const session = this.captureSession(res, body, {
      id: sessionId ?? `login-${user}`,
      label: label ?? "login",
      target,
      caseId,
    });
    if (!session.cookie && !session.accessToken) {
      // Login accepted but no session material returned — proof of existence only.
      return { ok: true };
    }
    store.saveSession(session);
    this.lastSessionId = session.id;
    return { ok: true, session };
  }

  async scan(input: EngageScanInput): Promise<OpResult> {
    if (!input.url) return err("scan requires url");
    const sid = input.sessionId ?? this.lastSessionId;
    const s = sid ? store.getSession(sid) : undefined;
    if (sid && !s) return err(`session ${sid} not found`);
    const headers = s ? (await resolveSessionRequest(s, this.fetchImpl)).headers : {};
    const res = await this.fetchImpl(input.url, {
      headers,
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    const h = Object.fromEntries(res.headers);
    const missing = BASE_SECURITY_HEADERS.filter((k) => !h[k]);
    return ok(`Passive scan of ${input.url}: ${missing.length ? "issues found" : "clean"}`, {
      missing,
      responseHeaders: h,
    });
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

export interface EngageSignupInput {
  signupUrl?: string;
  signupFields?: Record<string, string>;
  target?: string;
  label?: string;
  caseId?: string;
  sessionId?: string;
  /** auto (try response token, then inbox) | response | inbox | none */
  verifyStrategy?: "auto" | "response" | "inbox" | "none";
  /** Max time to wait for a verification email in the disposable inbox (ms). */
  verifyTimeoutMs?: number;
  /** Login endpoint. After signup the agent logs in with the same credentials to prove the account exists. */
  loginUrl?: string;
  /** Field map for the login POST body. Placeholders <EMAIL>, <USER>, <PASS> (filled from the signup). */
  loginFields?: Record<string, string>;
}

export interface EngageLoginInput {
  loginUrl?: string;
  loginFields?: Record<string, string>;
  target?: string;
  label?: string;
  caseId?: string;
  sessionId?: string;
}
