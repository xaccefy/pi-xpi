/**
 * pi-engage — autonomous web-pentest helper for Pi Agent (part of XPI).
 *
 * One tool that AUTHENTICATES and PENTESTS, all driven by the agent:
 *
 *   1. Session management (the human-supplied, sanctioned identity):
 *        add | get | list | token | delete | clear
 *        - cookie                   : replay a browser `Cookie` header
 *        - oauth-client-credentials : agent is its own service identity; self-refreshing
 *                                     bearer token, zero human at runtime (most autonomous)
 *        - mtls                     : client-certificate identity presented in the TLS handshake
 *
 *   2. Pentest, authenticated, using the tools you already have (pdtm suite):
 *        run   — run a curated pentest CLI (curl/httpx/ffuf) with auth injected
 *        send  — single authenticated HTTP request (returns a curl command too)
 *        spider— crawl in-scope links with the session applied
 *        scan  — fast passive security-header check (no external scanner)
 *
 * No MITM proxy required: the resolved auth (Bearer / cookie / mTLS flags) is
 * handed straight to curl and the pdtm tools, which capture their own output.
 *
 * Tools:   engage
 * Command: /engage
 */

import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { Text } from "@earendil-works/pi-tui";
import { type Static, Type } from "@sinclair/typebox";
import {
  Engage,
  type EngageLoginInput,
  type EngageRunInput,
  type EngageScanInput,
  type EngageSendInput,
  type EngageSetupInput,
  type EngageSignupInput,
  type EngageSpiderInput,
  type OpResult,
} from "./engage.ts";

/**
 * Provider-safe string enum (Kind "String"). Avoids Type.Union(Type.Literal...)
 * which compiles to anyOf/const that some providers drop. Mirrors pi-xtodo.
 */
function StringEnum<T extends readonly string[]>(values: T, options?: { description?: string }) {
  return Type.String({
    enum: [...values],
    ...(options?.description ? { description: options.description } : {}),
  });
}

export const TOOL_NAME = "engage";
export const COMMAND_NAME = "engage";

// Singleton so proxy/session state survives between tool calls.
const engage = new Engage();

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------
export const EngageParamsSchema = Type.Object({
  action: StringEnum(
    [
      "add",
      "get",
      "list",
      "token",
      "delete",
      "clear",
      "run",
      "send",
      "spider",
      "scan",
      "signup",
      "login",
    ] as const,
    {
      description:
        "Session: add|get|list|token|delete|clear — Pentest: run|send|spider|scan — Account: signup|login",
    },
  ),

  // session fields
  id: Type.Optional(Type.String({ description: "Session id (add | get | token | delete)" })),
  sessionId: Type.Optional(
    Type.String({ description: "Existing session id (setup | send | spider | scan)" }),
  ),
  label: Type.Optional(Type.String({ description: "Human label (add)" })),
  target: Type.Optional(
    Type.String({
      description: "Target host/domain, used in curl examples + proxy scope (add | setup override)",
    }),
  ),
  caseId: Type.Optional(
    Type.String({ description: "Linked casefile case id for this target (add)" }),
  ),
  mode: Type.Optional(
    StringEnum(["cookie", "oauth-client-credentials", "mtls"] as const, {
      description: "Auth mode (add)",
    }),
  ),
  cookie: Type.Optional(Type.String({ description: "Raw Cookie header (mode=cookie)" })),
  tokenUrl: Type.Optional(
    Type.String({ description: "OAuth token endpoint (mode=oauth-client-credentials)" }),
  ),
  clientId: Type.Optional(
    Type.String({ description: "OAuth client id (mode=oauth-client-credentials)" }),
  ),
  clientSecret: Type.Optional(
    Type.String({ description: "OAuth client secret (mode=oauth-client-credentials)" }),
  ),
  scope: Type.Optional(Type.String({ description: "OAuth scope (mode=oauth-client-credentials)" })),
  certPath: Type.Optional(Type.String({ description: "Client cert (PEM) path (mode=mtls)" })),
  keyPath: Type.Optional(Type.String({ description: "Client key (PEM) path (mode=mtls)" })),
  caPath: Type.Optional(
    Type.String({ description: "CA cert path for upstream verification (mode=mtls)" }),
  ),

  // run fields (pdtm tool bridge)
  tool: Type.Optional(
    Type.String({
      description: "Pentest CLI to run (curl | httpx | ffuf)",
    }),
  ),
  args: Type.Optional(
    Type.Array(Type.String(), {
      description: "Extra CLI args passed to `tool` after auth injection",
    }),
  ),

  // request fields
  url: Type.Optional(Type.String({ description: "Target URL (send | spider | scan)" })),
  method: Type.Optional(Type.String({ description: "HTTP method (send, default GET)" })),
  body: Type.Optional(Type.String({ description: "Request body (send)" })),
  headers: Type.Optional(
    Type.Record(Type.String(), Type.String(), { description: "Extra request headers (send)" }),
  ),

  // spider fields
  inScope: Type.Optional(
    Type.Array(Type.String(), { description: "In-scope hosts for spider (default: url host)" }),
  ),
  depth: Type.Optional(Type.Number({ description: "Spider max depth (default 2)" })),

  // signup fields (autonomous low-priv account creation)
  signupUrl: Type.Optional(
    Type.String({
      description: "Registration endpoint URL (signup). Agent creates a throwaway account.",
    }),
  ),
  signupFields: Type.Optional(
    Type.Record(Type.String(), Type.String(), {
      description:
        "Field map for the signup POST body. Use placeholders <EMAIL>, <USER>, <PASS> (auto-filled). e.g. { email: '<EMAIL>', password: '<PASS>', username: '<USER>' }",
    }),
  ),
  verifyStrategy: Type.Optional(
    StringEnum(["auto", "response", "inbox", "none"] as const, {
      description:
        "Verification: auto (response token, then disposable inbox) | response (token in signup body) | inbox (temp-mail poll) | none (skip)",
    }),
  ),
  verifyTimeoutMs: Type.Optional(
    Type.Number({ description: "Max time to wait for a verification email (ms, default 90000)" }),
  ),
  // login fields (prove a created account exists by logging in)
  loginUrl: Type.Optional(
    Type.String({
      description:
        "Login endpoint URL. After signup, the agent logs in with the same credentials to prove the account was created.",
    }),
  ),
  loginFields: Type.Optional(
    Type.Record(Type.String(), Type.String(), {
      description:
        "Field map for the login POST body. Use placeholders <EMAIL>, <USER>, <PASS> (auto-filled from the signup). e.g. { email: '<EMAIL>', password: '<PASS>' }",
    }),
  ),
});

export type EngageParams = Static<typeof EngageParamsSchema>;

// ---------------------------------------------------------------------------
// Result plumbing
// ---------------------------------------------------------------------------
interface ToolResult {
  content: { type: "text"; text: string }[];
  isError?: boolean;
  details: unknown;
}

function toResult(r: OpResult): ToolResult {
  return {
    content: [{ type: "text", text: r.text }],
    ...(r.isError ? { isError: true } : {}),
    details: r.details,
  };
}
function errResult(text: string, details?: unknown): ToolResult {
  return { content: [{ type: "text", text }], isError: true, details };
}

// ---------------------------------------------------------------------------
// Extension entry point
// ---------------------------------------------------------------------------
export default function piEngage(pi: ExtensionAPI) {
  pi.registerTool({
    name: TOOL_NAME,
    label: "Engage",
    description:
      "Authenticate to an authorized target and run web-pentest actions. Manage sessions (cookie / OAuth client-credentials / mTLS), then run curl / httpx / ffuf with the auth injected — no MITM proxy needed. The agent never invents or borrows credentials — a human supplies the target + identity.",
    promptSnippet: "Authenticate to a target and run web-pentest actions (sessions, proxy, scan)",
    promptGuidelines: [
      "Use `engage` to hold the credentials a USER supplies for an authorized target — never invent or borrow them.",
      "Resolve a session with `engage action=token`, then run tools directly: `engage action=run tool=httpx` / `tool=ffuf` inject the auth automatically.",
      "Use `engage action=send` for a single authenticated request; the result includes a ready `curl` command.",
      "Prefer oauth-client-credentials or mtls over cookie: they are the agent's own identity and need no human re-login.",
      "Link sessions to a casefile case with `caseId` so findings stay scoped to one engagement.",
      "`engage action=scan` runs a fast passive security-header check.",
    ],
    parameters: EngageParamsSchema,

    async execute(_toolCallId, params, _signal, _onUpdate, _ctx) {
      const p = params as EngageParams;
      try {
        switch (p.action) {
          case "add":
            return toResult(engage.addSession(p as EngageSetupInput));
          case "get":
            return toResult(engage.getSession(p.id ?? ""));
          case "list":
            return toResult(engage.listSessions());
          case "token":
            return toResult(await engage.token(p.id ?? ""));
          case "delete":
            return toResult(engage.deleteSession(p.id ?? ""));
          case "clear":
            return toResult(engage.clearSessions());
          case "run":
            return toResult(await engage.run(p as EngageRunInput));
          case "send":
            return toResult(await engage.send(p as EngageSendInput));
          case "spider":
            return toResult(await engage.spider(p as EngageSpiderInput));
          case "scan":
            return toResult(await engage.scan(p as EngageScanInput));
          case "signup":
            return toResult(await engage.signup(p as EngageSignupInput));
          case "login":
            return toResult(await engage.login(p as EngageLoginInput));
          default:
            return errResult(`unknown action: ${String(p.action)}`);
        }
      } catch (e) {
        const message = e instanceof Error ? e.message : String(e);
        return errResult(`engage error: ${message}`, { error: message });
      }
    },

    renderCall(args, theme) {
      const a = args as Partial<EngageParams>;
      const head = theme.fg("toolTitle", theme.bold("engage "));
      const tail = [a.action, a.id ?? a.label ?? a.url ?? ""].filter(Boolean).join(" ");
      return new Text(head + theme.fg("muted", tail), 0, 0);
    },

    renderResult(result, _options, theme) {
      const r = result as { isError?: boolean; details?: { mode?: string; tool?: string } };
      if (r.isError) {
        const details = (result as { details?: { error?: string } }).details;
        return new Text(theme.fg("error", `✗ engage failed: ${details?.error ?? ""}`), 0, 0);
      }
      const tag = r.details?.mode ?? r.details?.tool ?? "";
      return new Text(theme.fg("success", "✓") + theme.fg("dim", ` engage ${tag}`), 0, 0);
    },
  });

  pi.registerCommand(COMMAND_NAME, {
    description: "Show stored engage sessions",
    handler: async (_args, ctx: ExtensionContext) => {
      if (!ctx.hasUI) {
        ctx.ui.notify("/engage requires interactive mode", "error");
        return;
      }
      const sessions = engage.listSessions();
      ctx.ui.notify(sessions.text, "info");
    },
  });
}
