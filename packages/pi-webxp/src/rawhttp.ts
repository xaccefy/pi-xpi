/**
 * Byte-level raw HTTP transport for attack techniques fetch() cannot express.
 *
 * Two tools share one guarded socket layer:
 *
 * - `raw_request` sends the caller's bytes VERBATIM over one TCP/TLS socket.
 *   Request-smuggling probes (CL.TE / TE.CL desync), parser-differential
 *   attacks, and malformed-framing techniques require duplicate or
 *   contradictory framing headers — undici normalizes those away, so the
 *   agent needs real byte control.
 *
 * - `race_send` opens N sockets, transmits every request except its final
 *   byte, waits until all sockets are flushed, then issues the final bytes
 *   back-to-back within a single event-loop turn (last-byte sync). This is
 *   BATCH release, not a true single-packet send: per-socket kernel buffering
 *   adds spread on high-RTT targets. The report records each response's
 *   first-byte latency (`firstResponseMs`) and the burst's response spread
 *   (`responseSpreadMs`) so the caller can judge sync quality honestly.
 *
 * Safety model (same policy as http_request):
 * - The target hostname is resolved ONCE per call; EVERY answer must be
 *   public or the call fails closed (allowPrivateHosts=true overrides).
 * - Sockets dial the validated address directly, so no later re-resolution
 *   can redirect the connection (closes the Bun TOCTOU window by design).
 * - TLS verification defaults on; SNI uses the original hostname while the
 *   dial goes to the pinned address.
 */

import { lookup as dnsLookupAsync } from "node:dns/promises";
import { isIP, connect as netConnect, type Socket } from "node:net";
import { type TLSSocket, connect as tlsConnect } from "node:tls";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Text } from "@earendil-works/pi-tui";
import { isPublicIpAddress } from "@xaccefy/pi-shared";
import { Type } from "typebox";
import {
  DEFAULT_MAX_BODY as DEFAULT_MAX_RESPONSE_BYTES,
  MAX_BODY_HARD as MAX_RESPONSE_BYTES_HARD,
} from "./httprequest.ts";

const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_RESPONSE_WAIT_MS = 5_000;
const MAX_RAW_REQUEST_CHARS = 128 * 1024;
const MIN_RACE_REQUESTS = 2;
const MAX_RACE_REQUESTS = 32;

type PinnedAddress = { address: string };

type DialTarget = {
  url: URL;
  host: string;
  port: number;
  tls: boolean;
};

function parseDialTarget(target: string): DialTarget {
  const trimmed = target.trim();
  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    throw new Error(`target is not a valid URL: ${target}`);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error(`target protocol must be http: or https: (got ${url.protocol})`);
  }
  if (!url.hostname) throw new Error("target is missing a hostname");
  if (url.username || url.password) {
    throw new Error("target must not contain credentials (userinfo is not supported)");
  }
  const tls = url.protocol === "https:";
  const port = url.port ? Number(url.port) : tls ? 443 : 80;
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`target port is invalid: ${url.port}`);
  }
  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  return { url, host, port, tls };
}

/**
 * Resolve once and validate every answer. Returns the approved addresses;
 * callers dial one of these directly — never the hostname again.
 */
async function resolvePublicAddresses(
  host: string,
  allowPrivateHosts: boolean,
): Promise<PinnedAddress[]> {
  if (isIP(host)) {
    if (!allowPrivateHosts && !isPublicIpAddress(host)) {
      throw new Error(
        `Blocked: ${host} is a private/internal host. Set allowPrivateHosts=true to test internal targets.`,
      );
    }
    return [{ address: host }];
  }
  let answers: { address: string }[];
  try {
    answers = await dnsLookupAsync(host, { all: true, verbatim: true });
  } catch (e) {
    throw new Error(`DNS resolution failed for ${host}: ${(e as Error).message}`);
  }
  if (answers.length === 0) throw new Error(`DNS resolution returned no addresses for ${host}`);
  if (!allowPrivateHosts) {
    const blocked = answers.find((a) => !isPublicIpAddress(a.address));
    if (blocked) {
      throw new Error(
        `Blocked: ${host} resolved to private/internal address ${blocked.address}. Set allowPrivateHosts=true to test internal targets.`,
      );
    }
  }
  return answers.map((a) => ({ address: a.address }));
}

function dialSocket(
  target: DialTarget,
  address: PinnedAddress,
  verifyTls: boolean,
  timeoutMs: number,
): Promise<Socket> {
  return new Promise((resolve, reject) => {
    const onError = (err: Error) => {
      clearTimeout(timer);
      reject(err);
    };
    const timer = setTimeout(
      () => onError(new Error(`connect timed out after ${timeoutMs}ms`)),
      timeoutMs,
    );
    const onEstablished = (socket: Socket) => {
      clearTimeout(timer);
      // Detach the dial-stage error handler: a socket that dies LATER must
      // not have its single 'error' event consumed by this stale listener
      // (later stages would then never see the failure and hang forever).
      socket.removeListener("error", onError);
      socket.setTimeout(timeoutMs);
      resolve(socket);
    };
    if (target.tls) {
      const socket = tlsConnect({
        host: address.address,
        port: target.port,
        servername: isIP(target.host) ? undefined : target.host,
        rejectUnauthorized: verifyTls,
      }) as unknown as TLSSocket;
      socket.once("error", onError);
      socket.once("secureConnect", () => onEstablished(socket));
    } else {
      const socket = netConnect({ host: address.address, port: target.port });
      socket.once("error", onError);
      socket.once("connect", () => onEstablished(socket));
    }
  });
}

/**
 * Write one chunk and wait for flush, with HARD bounds: the stage-local
 * error listener is removed on settle (so it cannot starve a later stage of
 * the socket's one-shot 'error' event), and a timer guarantees termination
 * even when a half-dead socket never calls the write callback.
 */
function writeChunk(socket: Socket, chunk: Buffer, timeoutMs: number): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    let settled = false;
    const onError = (err: Error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.removeListener("error", onError);
      reject(err);
    };
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      socket.removeListener("error", onError);
      reject(new Error(`write timed out after ${timeoutMs}ms (connection likely reset)`));
    }, timeoutMs);
    socket.once("error", onError);
    socket.write(chunk, () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.removeListener("error", onError);
      resolve();
    });
  });
}

/** Split off the final byte so it can be withheld for synchronized release. */
function splitFinalByte(requestText: string): { head: Buffer; tail: Buffer } {
  const buf = Buffer.from(requestText, "utf8");
  if (buf.byteLength < 2) {
    throw new Error("request is too short to split for last-byte sync (need >= 2 bytes)");
  }
  return { head: buf.subarray(0, buf.byteLength - 1), tail: buf.subarray(buf.byteLength - 1) };
}

function validateRawRequest(requestText: string, label: string): void {
  if (typeof requestText !== "string" || requestText.trim().length === 0) {
    throw new Error(`${label}: request must be a non-empty string`);
  }
  if (requestText.length > MAX_RAW_REQUEST_CHARS) {
    throw new Error(`${label}: request exceeds ${MAX_RAW_REQUEST_CHARS} characters`);
  }
  // biome-ignore lint/suspicious/noControlCharactersInRegex: intentional — reject NUL bytes in raw payloads
  if (/\x00/.test(requestText)) {
    throw new Error(`${label}: request contains NUL bytes`);
  }
}

type ResponseCapture = {
  bytes: Buffer[];
  received: number;
  truncated: boolean;
  finished: boolean; // socket ended on its own
  /** Wall-clock ms of the first response chunk (sync-quality signal). */
  firstDataAt?: number;
  /** Wall-clock ms when the capture settled (finish/limit/error/timeout). */
  finishedAt?: number;
};

function captureResponse(
  socket: Socket,
  maxBytes: number,
  waitMs: number,
): {
  done: Promise<ResponseCapture>;
  cancel: () => void;
} {
  const cap: ResponseCapture = { bytes: [], received: 0, truncated: false, finished: false };
  let settled = false;
  const finish = () => {
    if (settled) return;
    settled = true;
    cap.finishedAt = Date.now();
    clearTimeout(waitTimer);
    socket.removeListener("data", onData);
    socket.removeListener("close", onClose);
    socket.removeListener("error", onError);
    resolveCap(cap);
  };
  const onData = (chunk: Buffer) => {
    cap.firstDataAt ??= Date.now();
    if (cap.truncated) return;
    const remaining = maxBytes - cap.received;
    if (remaining <= 0) {
      cap.truncated = true;
      finish();
      return;
    }
    const kept = chunk.byteLength > remaining ? chunk.subarray(0, remaining) : chunk;
    cap.bytes.push(kept);
    cap.received += kept.byteLength;
    if (cap.received >= maxBytes) {
      cap.truncated = true;
      finish();
    }
  };
  const onClose = () => {
    cap.finished = true;
    finish();
  };
  const onError = () => {
    // Connection errors after establishment end the capture; the bytes seen
    // so far remain the honest observation.
    finish();
  };
  const waitTimer = setTimeout(finish, waitMs);

  let resolveCap: (value: ResponseCapture) => void;
  const done = new Promise<ResponseCapture>((resolve) => {
    resolveCap = resolve;
  });

  socket.on("data", onData);
  socket.once("close", onClose);
  socket.once("error", onError);
  return {
    done,
    cancel: () => {
      socket.destroy();
    },
  };
}

export type RawHttpResponse = {
  status: number | undefined;
  statusLine: string;
  body: string;
  bodyBytes: number;
  truncated: boolean;
  /** True when the peer closed the connection (complete observation). */
  completed: boolean;
  timingMs: number;
};

function parseStatusLine(head: string): { status: number | undefined; statusLine: string } {
  const firstLineEnd = head.indexOf("\r\n");
  const statusLine = firstLineEnd === -1 ? head : head.slice(0, firstLineEnd);
  const match = /^HTTP\/[\d.]+ (\d{3})/.exec(statusLine);
  return { status: match ? Number(match[1]) : undefined, statusLine };
}

function summarizeCapture(cap: ResponseCapture, startedAt: number): RawHttpResponse {
  const body = Buffer.concat(cap.bytes).toString("utf8");
  const { status, statusLine } = parseStatusLine(body);
  return {
    status,
    statusLine,
    body,
    bodyBytes: cap.received,
    truncated: cap.truncated,
    completed: cap.finished,
    // Measured from the capture's own settle timestamp — NOT from map time
    // after Promise.all (which would report ~0 for every request and destroy
    // the response-side sync signal the report exists to carry).
    timingMs: (cap.finishedAt ?? Date.now()) - startedAt,
  };
}

/** Send one raw request over a fresh socket; bytes go out exactly as given. */
export async function sendRawRequest(
  target: string,
  rawRequest: string,
  opts: {
    timeoutMs?: number;
    responseWaitMs?: number;
    verifyTls?: boolean;
    allowPrivateHosts?: boolean;
    maxResponseBytes?: number;
  } = {},
): Promise<RawHttpResponse> {
  validateRawRequest(rawRequest, "raw");
  const dial = parseDialTarget(target);
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const waitMs = opts.responseWaitMs ?? DEFAULT_RESPONSE_WAIT_MS;
  const maxBytes = Math.min(
    opts.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES,
    MAX_RESPONSE_BYTES_HARD,
  );
  const verifyTls = opts.verifyTls !== false;

  const addresses = await resolvePublicAddresses(dial.host, opts.allowPrivateHosts === true);
  const startedAt = Date.now();
  const socket = await dialSocket(dial, addresses[0], verifyTls, timeoutMs);
  try {
    // Write FIRST, capture SECOND: the response window must not include flush
    // time (a slow large-request write would otherwise burn responseWaitMs
    // and report a misleading empty "hung" observation). Responses arriving
    // mid-write are safe — TCP flow control holds them until the socket is
    // read.
    await writeChunk(socket, Buffer.from(rawRequest, "utf8"), timeoutMs);
    const capture = captureResponse(socket, maxBytes, waitMs);
    const cap = await capture.done;
    return summarizeCapture(cap, startedAt);
  } finally {
    // No error path leaves the socket open: write failures and capture
    // exceptions both land here.
    socket.destroy();
  }
}

export type RaceSendResult = RawHttpResponse & {
  index: number;
  /** ms between the earliest final-byte release and this socket's release.
   * Always 0 by construction (all tails issue in one event-loop turn). */
  releaseOffsetMs: number;
  /** ms from the burst release to this response's FIRST byte, or null when
   * the socket produced no response data — the response-side sync signal. */
  firstResponseMs: number | null;
};

export type RaceSendReport = {
  results: RaceSendResult[];
  statuses: Record<string, number>;
  errors: string[];
  /** max−min firstResponseMs across responses that arrived; null when fewer
   * than two responses carried data (no spread to measure). */
  responseSpreadMs: number | null;
};

/**
 * Fire N raw requests with last-byte synchronization: every socket transmits
 * all but the final byte, waits for the flush, then the final bytes are issued
 * back-to-back within one event-loop turn. This is batch release — not a
 * single-syscall single-packet attack — so observed spread grows with RTT and
 * kernel buffering variance. The report records each response's first-byte
 * latency (firstResponseMs) and the response spread (responseSpreadMs);
 * treat large spreads as unsynchronized rather than claiming race precision
 * the transport did not deliver.
 */
export async function raceSendRequests(
  target: string,
  requests: string[],
  opts: {
    holdLastByte?: boolean;
    timeoutMs?: number;
    responseWaitMs?: number;
    verifyTls?: boolean;
    allowPrivateHosts?: boolean;
    maxResponseBytes?: number;
  } = {},
): Promise<RaceSendReport> {
  if (!Array.isArray(requests) || requests.length < MIN_RACE_REQUESTS) {
    throw new Error(`race_send needs at least ${MIN_RACE_REQUESTS} requests`);
  }
  if (requests.length > MAX_RACE_REQUESTS) {
    throw new Error(`race_send supports at most ${MAX_RACE_REQUESTS} concurrent requests`);
  }
  requests.forEach((r, i) => {
    validateRawRequest(r, `requests[${i}]`);
  });

  const dial = parseDialTarget(target);
  const holdLastByte = opts.holdLastByte !== false;
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const waitMs = opts.responseWaitMs ?? DEFAULT_RESPONSE_WAIT_MS;
  const maxBytes = Math.min(
    opts.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES,
    MAX_RESPONSE_BYTES_HARD,
  );
  const verifyTls = opts.verifyTls !== false;

  const addresses = await resolvePublicAddresses(dial.host, opts.allowPrivateHosts === true);

  // Open all sockets CONCURRENTLY — serial dialing would add N×RTT of skew
  // before the burst even starts, defeating the synchronization this tool
  // exists for. A failure anywhere fails the whole burst AND destroys every
  // already-open socket: a partially-released burst would poison the race
  // observation, and a leaked dial would hold a connection to the target.
  const sockets: Socket[] = [];
  try {
    const dialed = await Promise.allSettled(
      requests.map((_, i) =>
        dialSocket(dial, addresses[i % addresses.length], verifyTls, timeoutMs),
      ),
    );
    for (const d of dialed) if (d.status === "fulfilled") sockets.push(d.value);
    const failed = dialed.find((d) => d.status === "rejected");
    if (failed) {
      throw failed.reason;
    }

    const parts = requests.map((r) =>
      holdLastByte ? splitFinalByte(r) : { head: Buffer.from(r, "utf8"), tail: Buffer.alloc(0) },
    );

    // Phase 1: everything except the final byte, and WAIT for each flush so
    // the bytes are already sitting in the target's receive buffer.
    await Promise.all(sockets.map((s, i) => writeChunk(s, parts[i]!.head, timeoutMs)));

    // Captures start only now: responseWaitMs must measure the RESPONSE
    // window, not include head-flush time (large requests would otherwise
    // eat the wait budget before the race even fires).
    const captures = sockets.map((s) => captureResponse(s, maxBytes, waitMs));

    // Phase 2: release every final byte back-to-back in ONE event-loop turn.
    // socket.write() only queues to the kernel — it does not wait for the
    // peer — so issuing all tails without an intermediate await keeps the
    // inter-release skew at microseconds of JS dispatch rather than the
    // per-socket flush latency awaited writes would serialize on. Tail-write
    // errors surface through each socket's 'error' listener, which
    // captureResponse consumes; a failed tail simply ends that socket's
    // capture with whatever was observed (honest incomplete observation).
    for (const [i, s] of sockets.entries()) {
      if (parts[i]!.tail.byteLength > 0) s.write(parts[i]!.tail);
    }
    const releaseAt = Date.now();

    const settled = await Promise.all(captures.map((c) => c.done));
    for (const s of sockets) s.destroy();

    const burstStart = Date.now();
    const results: RaceSendResult[] = settled.map((cap, i) => ({
      index: i,
      // Batch release: every tail was issued in the same turn, so the
      // per-request dispatch offset is ~0 by construction. The honest sync
      // signal is response-side: firstResponseMs per request and
      // responseSpreadMs across the burst.
      releaseOffsetMs: 0,
      firstResponseMs: cap.firstDataAt !== undefined ? cap.firstDataAt - releaseAt : null,
      ...summarizeCapture(cap, burstStart),
    }));

    const arrived = results
      .map((r) => r.firstResponseMs)
      .filter((v): v is number => v !== null);
    const responseSpreadMs =
      arrived.length >= 2 ? Math.max(...arrived) - Math.min(...arrived) : null;

    const statuses: Record<string, number> = {};
    const errors: string[] = [];
    for (const r of results) {
      if (r.status !== undefined)
        statuses[String(r.status)] = (statuses[String(r.status)] ?? 0) + 1;
      else errors.push(`#${r.index}: no HTTP status in response`);
    }
    return {
      results,
      statuses,
      errors,
      responseSpreadMs,
    };
  } catch (e) {
    for (const s of sockets) s.destroy();
    throw e;
  }
}

// ── Tool registration ────────────────────────────────────────────────

const TargetParam = Type.String({
  description: "Target origin, e.g. https://example.com or http://10.0.0.1:8080",
});
const VerifyTlsParam = Type.Optional(
  Type.Boolean({
    description: "Verify TLS certificate (default true). Set false for self-signed targets.",
  }),
);
const AllowPrivateParam = Type.Optional(
  Type.Boolean({
    description:
      "Allow private/internal hosts (default false, SSRF-safe). Set true for lab/internal targets.",
  }),
);
const TimeoutParam = Type.Optional(
  Type.Integer({ minimum: 500, maximum: 120000, description: "Connect/write timeout in ms" }),
);
const WaitParam = Type.Optional(
  Type.Integer({
    minimum: 100,
    maximum: 60000,
    description:
      "How long to keep reading the response after release (ms). A smuggling hang shows up as completed:false.",
  }),
);
const MaxBytesParam = Type.Optional(
  Type.Integer({
    minimum: 1024,
    maximum: MAX_RESPONSE_BYTES_HARD,
    description: "Max captured response bytes",
  }),
);

export default function rawHttpExtension(pi: ExtensionAPI) {
  pi.registerTool({
    name: "raw_request",
    label: "Raw Request",
    description:
      "Send a raw HTTP request over a direct TCP/TLS socket with BYTE-EXACT control — nothing is normalized, corrected, or re-framed. Use for request-smuggling probes (CL.TE/TE.CL desync), parser differentials, malformed framing, and any technique needing duplicate/contradictory headers that fetch cannot express. The response is captured verbatim until the peer closes or responseWaitMs elapses; a hung socket (completed:false) is itself the classic desync signal.",
    promptSnippet: "Send byte-exact raw HTTP over a socket (smuggling/desync probes)",
    promptGuidelines: [
      "Provide the FULL request including request line, headers, and terminating blank line: 'POST /x HTTP/1.1\\r\\nHost: t\\r\\nContent-Length: 4\\r\\n\\r\\nABCD'. Nothing is auto-corrected — wrong Content-Length is your technique, not an error.",
      "Timing probe first: a partial TE.CL payload makes the socket hang waiting for bytes — completed:false plus a distinct delay indicates front/back-end disagreement.",
      "Confirm impact before reporting: smuggle an attributable prefix (e.g. force the next request to GET /<your-canary>) and observe the effect on a request you control.",
      "Private/internal hosts are blocked unless allowPrivateHosts=true; DNS is resolved once and every answer must be public — the socket dials the validated IP directly.",
    ],
    parameters: Type.Object(
      {
        target: TargetParam,
        raw: Type.String({
          description: "The complete raw HTTP request text, sent byte-for-byte as provided.",
        }),
        timeoutMs: TimeoutParam,
        responseWaitMs: WaitParam,
        verifyTls: VerifyTlsParam,
        allowPrivateHosts: AllowPrivateParam,
        maxResponseBytes: MaxBytesParam,
      },
      { additionalProperties: false },
    ),

    async execute(_id, params, _signal, _onUpdate, _ctx) {
      try {
        const result = await sendRawRequest(params.target as string, params.raw as string, {
          timeoutMs: params.timeoutMs as number | undefined,
          responseWaitMs: params.responseWaitMs as number | undefined,
          verifyTls: params.verifyTls !== false,
          allowPrivateHosts: params.allowPrivateHosts === true,
          maxResponseBytes: params.maxResponseBytes as number | undefined,
        });
        const note = result.completed
          ? "peer closed the connection"
          : "socket still open at responseWaitMs — for smuggling probes this hang IS the signal";
        const text =
          `< ${result.statusLine || "(no valid status line)"}\n` +
          `${result.body}` +
          (result.truncated ? `\n\n[body truncated at capture limit]` : "") +
          `\n\n[${note}; ${result.timingMs}ms, ${result.bodyBytes} bytes]`;
        return {
          content: [{ type: "text" as const, text }],
          details: { ...result, note },
        };
      } catch (err) {
        throw new Error(`raw_request failed: ${(err as Error).message}`, { cause: err });
      }
    },

    renderCall(args, theme) {
      return new Text(
        theme.fg("toolTitle", theme.bold("RAW ")) +
          theme.fg("dim", ((args.target as string) ?? "").slice(0, 60)),
        0,
        0,
      );
    },

    renderResult(result, _opts, theme, context) {
      if (context.isError) return new Text(theme.fg("error", "✗ raw failed"), 0, 0);
      const d = result.details as { status?: number; completed?: boolean } | undefined;
      const color = d?.status && d.status < 400 ? "success" : "warning";
      return new Text(
        theme.fg(color, String(d?.status ?? "?")) +
          theme.fg("dim", d?.completed ? " complete" : " open/hung"),
        0,
        0,
      );
    },
  });

  pi.registerTool({
    name: "race_send",
    label: "Race Send",
    description:
      "Fire 2-32 raw HTTP requests with LAST-BYTE SYNC: all sockets transmit everything except the final byte, wait for flush, then the final bytes are issued back-to-back within one event-loop turn. This is batch release, not a true single-packet send — judge synchronization by the reported response-side spread (responseSpreadMs / firstResponseMs) before claiming race timing. Use to exploit TOCTOU windows (coupon redemption xN, balance overdraft, invite acceptance, vote/limit bypass). Sequential requests cannot hit these windows; this tool can. Pair with the race-conditions methodology: prove the over-limit END STATE, then show a serial baseline does not reach it.",
    promptSnippet: "Release N synchronized raw requests (last-byte sync race attack)",
    promptGuidelines: [
      "Each entry must be a COMPLETE raw request (request line, Host header, framing headers, body). Vary per-request values (e.g. coupon codes) inside the entries, not by editing after send.",
      "Report requires the differential: burst reaching the illegitimate state vs the same request sent serially via raw_request producing a single success. Record concurrency and the observed release spread.",
      "Races are probabilistic — reproduce at least twice before claiming confirmation, and state the observed success count honestly.",
      "holdLastByte=false sends each request immediately after connect (no sync); keep the default true for actual races.",
      "Check the reported response-side spread BEFORE claiming synchronization: batch release adds per-socket buffering skew, and a wide responseSpreadMs (or nulls in firstResponseMs) means the burst was effectively sequential.",
    ],
    parameters: Type.Object(
      {
        target: TargetParam,
        requests: Type.Array(Type.String(), {
          minItems: MIN_RACE_REQUESTS,
          maxItems: MAX_RACE_REQUESTS,
          description: "2-32 complete raw HTTP request texts, released with last-byte sync.",
        }),
        holdLastByte: Type.Optional(
          Type.Boolean({
            description:
              "Withhold each final byte until all sockets are flushed, then release together (default true).",
          }),
        ),
        timeoutMs: TimeoutParam,
        responseWaitMs: WaitParam,
        verifyTls: VerifyTlsParam,
        allowPrivateHosts: AllowPrivateParam,
        maxResponseBytes: MaxBytesParam,
      },
      { additionalProperties: false },
    ),

    async execute(_id, params, _signal, _onUpdate, _ctx) {
      try {
        const report = await raceSendRequests(
          params.target as string,
          params.requests as string[],
          {
            holdLastByte: params.holdLastByte !== false,
            timeoutMs: params.timeoutMs as number | undefined,
            responseWaitMs: params.responseWaitMs as number | undefined,
            verifyTls: params.verifyTls !== false,
            allowPrivateHosts: params.allowPrivateHosts === true,
            maxResponseBytes: params.maxResponseBytes as number | undefined,
          },
        );
        const spread = report.responseSpreadMs;
        const lines = report.results
          .map(
            (r) =>
              `#${r.index} ${r.status ?? "?"} (resp +${r.firstResponseMs ?? "—"}ms, ${r.bodyBytes}B)`,
          )
          .join("\n");
        const text =
          `released ${report.results.length} requests, response spread ${spread ?? "n/a"}ms\n` +
          `${lines}\n` +
          `statuses: ${JSON.stringify(report.statuses)}${report.errors.length ? `\nerrors: ${report.errors.join("; ")}` : ""}`;
        return {
          content: [{ type: "text" as const, text }],
          details: report,
        };
      } catch (err) {
        throw new Error(`race_send failed: ${(err as Error).message}`, { cause: err });
      }
    },

    renderCall(args, theme) {
      const n = Array.isArray(args.requests) ? args.requests.length : 0;
      return new Text(
        theme.fg("toolTitle", theme.bold("RACE ")) +
          theme.fg("dim", `x${n} `) +
          theme.fg("dim", ((args.target as string) ?? "").slice(0, 50)),
        0,
        0,
      );
    },

    renderResult(result, _opts, theme, context) {
      if (context.isError) return new Text(theme.fg("error", "✗ race failed"), 0, 0);
      const d = result.details as
        | { results?: { firstResponseMs?: number | null }[]; responseSpreadMs?: number | null; statuses?: Record<string, number> }
        | undefined;
      const spread = d?.responseSpreadMs ?? "n/a";
      return new Text(
        theme.fg("success", "✓ burst ") +
          theme.fg("dim", `resp spread ${spread}ms ${JSON.stringify(d?.statuses ?? {})}`),
        0,
        0,
      );
    },
  });
}
