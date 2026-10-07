import assert from "node:assert";
import type { AddressInfo, Server } from "node:net";
import net from "node:net";
import { afterEach, beforeEach, describe, it } from "node:test";
import { MockExtensionAPI } from "../../../test-utils.ts";
import piWebxp from "../src/index.ts";

/**
 * Raw TCP server that echoes an HTTP response once a connection's buffer
 * ends with the final byte of a request (per-connection). Records every
 * byte received and completion timestamps so tests can assert verbatim
 * transport and burst synchronization quality.
 */
function startRawServer(response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"): Promise<{
  server: Server;
  port: number;
  received: string[];
  completedAt: number[];
}> {
  return new Promise((resolve) => {
    const received: string[] = [];
    const completedAt: number[] = [];
    const server = net.createServer((socket) => {
      let buf = "";
      socket.on("data", (d: Buffer) => {
        buf += d.toString("utf8");
        if (buf.endsWith("\n")) {
          received.push(buf);
          completedAt.push(performance.now());
          socket.end(response);
          buf = "";
        }
      });
    });
    server.listen(0, "127.0.0.1", () => {
      resolve({ server, port: (server.address() as AddressInfo).port, received, completedAt });
    });
  });
}

/** Raw TCP server that responds after ANY bytes arrive, recording them exactly. */
function startByteCaptureServer(): Promise<{
  server: Server;
  port: number;
  received: () => string;
}> {
  let captured = "";
  return new Promise((resolve) => {
    const server = net.createServer((socket) => {
      socket.on("data", (d: Buffer) => {
        captured += d.toString("utf8");
        socket.end("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
      });
    });
    server.listen(0, "127.0.0.1", () => {
      resolve({ server, port: (server.address() as AddressInfo).port, received: () => captured });
    });
  });
}

describe("pi-webxp: raw_request / race_send", () => {
  let api: MockExtensionAPI;
  const started: Server[] = [];

  beforeEach(() => {
    api = new MockExtensionAPI();
    piWebxp(api as any);
    // Loopback test servers are private hosts: the operator gate must be
    // open for these tests, exactly as an internal-lab operator would.
    process.env.PI_WEBXP_ALLOW_PRIVATE_HOSTS = "1";
  });

  afterEach(async () => {
    delete process.env.PI_WEBXP_ALLOW_PRIVATE_HOSTS;
    await Promise.all(
      started.splice(0).map((s) => new Promise<void>((resolve) => s.close(() => resolve()))),
    );
  });

  /** Server that consumes requests but never responds; `ready` resolves once
 * `minHeads` connections delivered bytes — proof the sockets are established
 * and head writes flushed, so a test can abort deterministically mid-capture
 * instead of racing the dial phase. */
function startHoldingServer(minHeads: number): Promise<{
  server: Server;
  port: number;
  ready: Promise<void>;
}> {
  return new Promise((resolve) => {
    let heads = 0;
    let readyResolve: () => void;
    const ready = new Promise<void>((r) => {
      readyResolve = r;
    });
    const server = net.createServer((socket) => {
      socket.on("data", () => {
        heads += 1;
        if (heads >= minHeads) readyResolve();
      });
      socket.on("error", () => undefined);
    });
    server.listen(0, "127.0.0.1", () => {
      resolve({ server, port: (server.address() as AddressInfo).port, ready });
    });
  });
}

function tool(name: string) {
    const t = api.tools.find((x) => x.name === name);
    assert.ok(t, `${name} registered`);
    return t!;
  }

  it("registers raw_request and race_send", () => {
    tool("raw_request");
    tool("race_send");
  });

  it("sends bytes VERBATIM — contradictory framing headers reach the wire untouched", async () => {
    const { server, port, received } = await startByteCaptureServer();
    started.push(server);

    // Classic CL.TE smuggling probe: duplicate/contradictory framing headers.
    // fetch() would reject or normalize this; the raw transport must not.
    const probe =
      "POST /smuggle HTTP/1.1\r\n" +
      "Host: localhost\r\n" +
      "Content-Length: 44\r\n" +
      "Transfer-Encoding: chunked\r\n" +
      "\r\n" +
      "0\r\n" +
      "\r\n" +
      "GET /canary HTTP/1.1\r\n" +
      "X: y";

    const res = await tool("raw_request").execute(
      "r1",
      { target: `http://127.0.0.1:${port}`, raw: probe, allowPrivateHosts: true },
      null,
      () => {},
      {},
    );
    assert.ok(!("isError" in (res as any)));
    assert.equal((res as any).details.status, 200);
    assert.equal(received(), probe, "wire bytes must equal the caller's bytes exactly");
  });

  it("reports a hung socket as completed:false (desync timing signal)", async () => {
    const server = net.createServer(() => {
      /* accept and never respond */
    });
    const port = await new Promise<number>((resolve) => {
      server.listen(0, "127.0.0.1", () => resolve((server.address() as AddressInfo).port));
    });
    started.push(server);

    const res = await tool("raw_request").execute(
      "r2",
      {
        target: `http://127.0.0.1:${port}`,
        raw: "GET /hang HTTP/1.1\r\nHost: t\r\n\r\n",
        allowPrivateHosts: true,
        responseWaitMs: 400,
      },
      null,
      () => {},
      {},
    );
    assert.ok(!("isError" in (res as any)));
    const d = (res as any).details;
    assert.equal(d.completed, false, "no response within wait window -> completed:false");
    assert.equal(d.status, undefined);
    assert.match(d.note as string, /hang IS the signal/);
  });

  it("blocks private hosts unless allowPrivateHosts=true", async () => {
    await assert.rejects(
      tool("raw_request").execute(
        "p1",
        { target: "http://127.0.0.1:9", raw: "GET / HTTP/1.1\r\nHost: x\r\n\r\n" },
        null,
        () => {},
        {},
      ),
      /private\/internal/,
    );
    await assert.rejects(
      tool("race_send").execute(
        "p2",
        {
          target: "http://127.0.0.1:9",
          requests: ["GET / HTTP/1.1\r\nHost: x\r\n\r\n", "GET / HTTP/1.1\r\nHost: x\r\n\r\n"],
        },
        null,
        () => {},
        {},
      ),
      /private\/internal/,
    );
  });

  it("rejects allowPrivateHosts=true without the operator gate", async () => {
    const previous = process.env.PI_WEBXP_ALLOW_PRIVATE_HOSTS;
    delete process.env.PI_WEBXP_ALLOW_PRIVATE_HOSTS;
    try {
      await assert.rejects(
        tool("raw_request").execute(
          "g1",
          {
            target: "http://127.0.0.1:9",
            raw: "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
            allowPrivateHosts: true,
          },
          null,
          () => {},
          {},
        ),
        /PI_WEBXP_ALLOW_PRIVATE_HOSTS=1/,
      );
      await assert.rejects(
        tool("race_send").execute(
          "g2",
          {
            target: "http://127.0.0.1:9",
            requests: ["GET / HTTP/1.1\r\nHost: x\r\n\r\n", "GET / HTTP/1.1\r\nHost: x\r\n\r\n"],
            allowPrivateHosts: true,
          },
          null,
          () => {},
          {},
        ),
        /PI_WEBXP_ALLOW_PRIVATE_HOSTS=1/,
      );
    } finally {
      if (previous !== undefined) process.env.PI_WEBXP_ALLOW_PRIVATE_HOSTS = previous;
    }
  });

  it("honors an already-aborted signal without touching the network", async () => {
    const controller = new AbortController();
    controller.abort();
    await assert.rejects(
      tool("raw_request").execute(
        "a1",
        { target: "http://93.184.216.34:9", raw: "GET / HTTP/1.1\r\nHost: x\r\n\r\n" },
        controller.signal,
        () => {},
        {},
      ),
      /aborted/,
    );
    await assert.rejects(
      tool("race_send").execute(
        "a2",
        {
          target: "http://93.184.216.34:9",
          requests: ["GET / HTTP/1.1\r\nHost: x\r\n\r\n", "GET / HTTP/1.1\r\nHost: x\r\n\r\n"],
        },
        controller.signal,
        () => {},
        {},
      ),
      /aborted/,
    );
  });

  it("aborts a race burst mid-capture and destroys every socket", async () => {
    const { server, port, ready } = await startHoldingServer(2);
    started.push(server);
    const controller = new AbortController();
    const pending = assert.rejects(
      tool("race_send").execute(
        "a3",
        {
          target: `http://127.0.0.1:${port}`,
          requests: Array.from({ length: 2 }, () => "GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
          responseWaitMs: 3000,
        },
        controller.signal,
        () => {},
        {},
      ),
      /aborted/,
    );
    // Synchronize on the server receiving head bytes: aborting earlier would
    // race the dial phase rather than exercise mid-capture cancellation.
    await ready;
    controller.abort();
    await pending;
  });

  it("aborts raw_request during the response wait", async () => {
    const { server, port, ready } = await startHoldingServer(1);
    started.push(server);
    const controller = new AbortController();
    const pending = assert.rejects(
      tool("raw_request").execute(
        "a4",
        {
          target: `http://127.0.0.1:${port}`,
          raw: "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
          responseWaitMs: 3000,
        },
        controller.signal,
        () => {},
        {},
      ),
      /aborted/,
    );
    await ready;
    controller.abort();
    await pending;
  });

  it("rejects invalid targets and requests", async () => {
    await assert.rejects(
      tool("raw_request").execute(
        "i1",
        { target: "ftp://x", raw: "GET / HTTP/1.1\r\n\r\n" },
        null,
        () => {},
        {},
      ),
      /protocol must be http/,
    );
    await assert.rejects(
      tool("raw_request").execute(
        "i2",
        { target: "http://127.0.0.1:9", raw: "" },
        null,
        () => {},
        {},
      ),
      /non-empty string/,
    );
    await assert.rejects(
      tool("race_send").execute(
        "i3",
        { target: "http://127.0.0.1:9", requests: ["only one"] },
        null,
        () => {},
        {},
      ),
      /at least 2/,
    );
    await assert.rejects(
      tool("race_send").execute(
        "i4",
        { target: "http://127.0.0.1:9", requests: ["a".repeat(200_000), "b"] },
        null,
        () => {},
        {},
      ),
      /exceeds/,
    );
  });

  it("race_send releases all requests with last-byte sync and collects every response", async () => {
    const { server, port, received, completedAt } = await startRawServer();
    started.push(server);

    const mk = (i: number) =>
      `POST /redeem HTTP/1.1\r\nHost: t\r\nContent-Length: 10\r\nCoupon: C${i}\r\n\r\nBODY-${i}\n`;
    const requests = Array.from({ length: 8 }, (_, i) => mk(i));

    const res = await tool("race_send").execute(
      "z1",
      { target: `http://127.0.0.1:${port}`, requests, allowPrivateHosts: true },
      null,
      () => {},
      {},
    );
    assert.ok(!("isError" in (res as any)));
    const d = (res as any).details;

    assert.equal(d.results.length, 8, "one observation per request");
    assert.deepEqual(d.statuses, { "200": 8 }, "every synchronized request got its response");
    assert.equal(received.length, 8, "server saw every complete request");
    for (const r of d.results) {
      assert.equal(typeof r.releaseOffsetMs, "number");
      assert.ok(r.releaseOffsetMs >= 0);
      // Response-side sync signal: first-byte latency from burst release.
      assert.ok(
        r.firstResponseMs === null || typeof r.firstResponseMs === "number",
        "firstResponseMs is a number or null",
      );
      if (r.firstResponseMs !== null) assert.ok(r.firstResponseMs >= 0);
    }
    // Every request got a 200 → every response carried data → spread must be
    // a measured number (not null) and non-negative.
    assert.equal(typeof d.responseSpreadMs, "number");
    assert.ok((d.responseSpreadMs as number) >= 0);

    // Sync quality: server-side completion timestamps should cluster tightly
    // compared to sequential dialing (generous bound for CI scheduler jitter).
    const spread = Math.max(...completedAt) - Math.min(...completedAt);
    assert.ok(
      spread < 2000,
      `server-side completion spread ${spread}ms should be well under serial time`,
    );
  });

  it("race_send without holdLastByte still delivers every request", async () => {
    const { server, port, statuses } = await (async () => {
      const received: string[] = [];
      const server = net.createServer((socket) => {
        let buf = "";
        socket.on("data", (d: Buffer) => {
          buf += d.toString("utf8");
          if (buf.endsWith("\n")) {
            received.push(buf);
            socket.end("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n");
            buf = "";
          }
        });
      });
      const port = await new Promise<number>((resolve) => {
        server.listen(0, "127.0.0.1", () => resolve((server.address() as AddressInfo).port));
      });
      return { server, port, statuses: received };
    })();
    started.push(server);

    const res = await tool("race_send").execute(
      "z2",
      {
        target: `http://127.0.0.1:${port}`,
        requests: [
          "GET /a HTTP/1.1\r\nHost: t\r\n\r\n",
          "GET /b HTTP/1.1\r\nHost: t\r\n\r\n",
          "GET /c HTTP/1.1\r\nHost: t\r\n\r\n",
        ],
        holdLastByte: false,
        allowPrivateHosts: true,
      },
      null,
      () => {},
      {},
    );
    assert.ok(!("isError" in (res as any)));
    assert.equal((res as any).details.results.length, 3);
    assert.deepEqual((res as any).details.statuses, { "204": 3 });
    assert.equal(statuses.length, 3);
  });
});
