/**
 * Attack-transport soundness suite — real sockets, real wire bytes.
 *
 * raw_request (byte-exact transport) and race_send (last-byte batch release)
 * are flagship XPI capabilities with no bench coverage: everything here runs
 * against throwaway node:net servers on ephemeral 127.0.0.1 ports, so the
 * REAL dial → write → hold-last-byte → burst-release → capture pipeline is
 * exercised end-to-end, not a fetch mock.
 *
 * Run: bun bench/transport-run.ts [--json]
 */

import type { AddressInfo } from "node:net";
import { createServer, type Server } from "node:net";
import { raceSendRequests, sendRawRequest } from "../packages/pi-webxp/src/rawhttp.ts";

type ScenarioResult = { id: string; claim: string; pass: boolean; note: string };

function listenEphemeral(server: Server): Promise<number> {
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve((server.address() as AddressInfo).port));
  });
}

/**
 * 1 — byte-exactness: the server echoes the RAW request bytes it received as
 * the response body. Any normalization (CRLF rewriting, header reordering,
 * whitespace folding) by the transport breaks the equality.
 */
async function rawVerbatim(): Promise<ScenarioResult> {
  const server = createServer((socket) => {
    let captured = Buffer.alloc(0);
    let timer: ReturnType<typeof setTimeout> | undefined;
    socket.on("data", (chunk) => {
      captured = Buffer.concat([captured, chunk]);
      clearTimeout(timer);
      // Reply after a short silence: the whole request (head + body) is in.
      timer = setTimeout(() => {
        const head = `HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: ${captured.byteLength}\r\n\r\n`;
        // ONE end() call: a second end() after the first is silently dropped,
        // truncating the response to just the header block.
        socket.end(Buffer.concat([Buffer.from(head), captured]));
      }, 150);
    });
    socket.on("error", () => undefined);
  });
  const port = await listenEphemeral(server);
  try {
    const body = 'payload={"crlf":"\r\nEND"}';
    const raw =
      "POST /upload?x=1 HTTP/1.1\r\n" +
      `Host: 127.0.0.1:${port}\r\n` +
      "X-Odd:\ttabbed value  \r\n" +
      "X-Dup: first\r\n" +
      "X-Dup: second\r\n" +
      `Content-Length: ${Buffer.byteLength(body)}\r\n` +
      "\r\n" +
      body;
    const res = await sendRawRequest(`http://127.0.0.1:${port}`, raw, {
      allowPrivateHosts: true,
      timeoutMs: 5000,
      responseWaitMs: 2000,
    });
    // res.body is the full wire response; strip the known envelope and
    // compare what the server captured against what we sent.
    const envelope = (n: number) =>
      `HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: ${n}\r\n\r\n`;
    const echoed = res.body.startsWith(envelope(raw.length))
      ? res.body.slice(envelope(raw.length).length)
      : undefined;
    const pass = echoed === raw && res.completed === true;
    return {
      id: "raw-verbatim-bytes",
      claim: "raw_request delivers bytes verbatim (CRLF, tabs, duplicate headers preserved)",
      pass,
      note: pass
        ? `${Buffer.byteLength(raw)} bytes round-tripped exactly`
        : `echo mismatch (${res.bodyBytes} response bytes for ${raw.length} sent, completed=${res.completed})`,
    };
  } finally {
    server.close();
  }
}

/**
 * 2 — race concurrency: an atomic counter assigns each request that COMPLETES
 * a unique sequence number. All N responses with distinct numbers prove every
 * burst member was processed — no dropped or serialized releases.
 */
async function raceBurst(): Promise<ScenarioResult> {
  let counter = 0;
  const server = createServer((socket) => {
    let buffered = "";
    socket.on("data", (chunk) => {
      buffered += chunk.toString("utf8");
      if (!buffered.includes("\r\n\r\n")) return;
      const n = ++counter;
      const body = `COUNT:${n}`;
      socket.end(
        `HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: ${body.length}\r\n\r\n${body}`,
      );
    });
    socket.on("error", () => undefined);
  });
  const port = await listenEphemeral(server);
  try {
    const reqs = Array.from(
      { length: 8 },
      (_, i) =>
        `POST /buy HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nContent-Length: 9\r\nX-N: ${i}\r\n\r\ncount=up`,
    );
    const report = await raceSendRequests(`http://127.0.0.1:${port}`, reqs, {
      allowPrivateHosts: true,
      timeoutMs: 5000,
      responseWaitMs: 2000,
    });
    const counters = report.results
      .map((r) => Number(/COUNT:(\d+)/.exec(r.body)?.[1] ?? NaN))
      .sort((a, b) => a - b);
    const allArrived =
      report.errors.length === 0 &&
      report.results.length === 8 &&
      report.statuses["200"] === 8 &&
      counters.every((n, i) => n === i + 1);
    const timings = report.results.map((r) => r.timingMs);
    const spreadMs = Math.max(...timings) - Math.min(...timings);
    return {
      id: "race-burst-delivery",
      claim: "race_send releases and lands all 8 requests concurrently (batch delivery)",
      pass: allArrived,
      note: allArrived
        ? `8/8 delivered, distinct sequence 1..8, observed response spread ${spreadMs}ms`
        : `errors=${report.errors.length} statuses=${JSON.stringify(report.statuses)} counters=${counters.join(",")}`,
    };
  } finally {
    server.close();
  }
}

export type TransportReport = {
  total: number;
  passed: number;
  score: number;
  results: ScenarioResult[];
};

export async function runTransportSuite(): Promise<TransportReport> {
  const results: ScenarioResult[] = [];
  for (const scenario of [rawVerbatim, raceBurst]) {
    try {
      results.push(await scenario());
    } catch (e) {
      results.push({
        id: scenario.name,
        claim: "(scenario threw)",
        pass: false,
        note: (e as Error).message,
      });
    }
  }
  const passed = results.filter((r) => r.pass).length;
  return { total: results.length, passed, score: passed / results.length, results };
}

if (import.meta.main) {
  const report = await runTransportSuite();
  const out = (s: string) => console.log(s);
  for (const r of report.results) {
    out(`[${r.pass ? "PASS" : "FAIL"}] ${r.id.padEnd(24)} ${r.pass ? r.note : `— ${r.note}`}`);
  }
  out(`SCORE ${report.passed}/${report.total} = ${(report.score * 100).toFixed(1)}%`);
  if (report.passed !== report.total) process.exit(1);
}
