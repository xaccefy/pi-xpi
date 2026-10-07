import assert from "node:assert";
import { afterEach, describe, it } from "node:test";
import {
  fetchInteractions,
  provisionCallback,
  readOobOracleConfig,
  setOobOracleFetchForTest,
  type OobOracleConfig,
} from "../src/oob-oracle.ts";

const GATE_KEYS = [
  "PI_OOB_ORACLE_URL",
  "PI_OOB_ORACLE_TOKEN",
  "PI_OOB_SOURCE_SEPARATED",
  "PI_OOB_SELF_IPS",
] as const;

function withEnv(env: Record<string, string>, fn: () => void): void {
  const saved: Record<string, string | undefined> = {};
  for (const key of GATE_KEYS) {
    saved[key] = process.env[key];
    if (env[key] === undefined) delete process.env[key];
    else process.env[key] = env[key];
  }
  try {
    fn();
  } finally {
    for (const key of GATE_KEYS) {
      if (saved[key] === undefined) delete process.env[key];
      else process.env[key] = saved[key];
    }
  }
}

describe("oob-oracle: readOobOracleConfig transport rules", () => {
  it("accepts https origins", () => {
    withEnv({ PI_OOB_ORACLE_URL: "https://oracle.example" }, () => {
      const { config, error } = readOobOracleConfig();
      assert.strictEqual(error, undefined);
      assert.strictEqual(config?.baseUrl, "https://oracle.example");
    });
  });

  it("accepts plaintext http only on exact loopback endpoints", () => {
    for (const url of ["http://localhost:9953", "http://127.0.0.1:9953", "http://127.8.9.10:1", "http://[::1]:9953"]) {
      withEnv({ PI_OOB_ORACLE_URL: url }, () => {
        assert.strictEqual(readOobOracleConfig().error, undefined, url);
      });
    }
  });

  it("rejects plaintext http for names that merely look loopback-ish", () => {
    // A DNS name is not an address: subdomains of localhost and hostnames
    // with a 127. prefix must not unlock plaintext HTTP.
    for (const url of [
      "http://sys.localhost",
      "http://127.0.0.1.evil.com",
      "http://localhost.evil.com",
      "http://loopback.example",
    ]) {
      withEnv({ PI_OOB_ORACLE_URL: url }, () => {
        const { config, error } = readOobOracleConfig();
        assert.strictEqual(config, undefined, url);
        assert.match(error ?? "", /must use https/, url);
      });
    }
  });

  it("rejects plaintext http on a remote host", () => {
    withEnv({ PI_OOB_ORACLE_URL: "http://oracle.example" }, () => {
      const { config, error } = readOobOracleConfig();
      assert.strictEqual(config, undefined);
      assert.match(error ?? "", /must use https/);
    });
  });

  it("rejects URLs carrying userinfo", () => {
    withEnv({ PI_OOB_ORACLE_URL: "https://operator:secret@oracle.example" }, () => {
      const { config, error } = readOobOracleConfig();
      assert.strictEqual(config, undefined);
      assert.match(error ?? "", /userinfo/);
    });
  });

  it("never echoes the raw URL (or its credentials) in parse errors", () => {
    withEnv({ PI_OOB_ORACLE_URL: "https://admin:hunter2@ bad url" }, () => {
      const { error } = readOobOracleConfig();
      assert.match(error ?? "", /not a valid URL/);
      assert.ok(!JSON.stringify(error ?? "").includes("hunter2"));
    });
  });

  it("reports a missing oracle with setup guidance", () => {
    withEnv({}, () => {
      assert.match(readOobOracleConfig().error ?? "", /PI_OOB_ORACLE_URL/);
    });
  });
});

describe("oob-oracle: error redaction", () => {
  afterEach(() => {
    setOobOracleFetchForTest(undefined);
  });

  it("unreachable-oracle errors carry the origin, never the token query", async () => {
    setOobOracleFetchForTest(async () => {
      throw new Error("connect ECONNREFUSED");
    });
    const config: OobOracleConfig = {
      baseUrl: "https://oracle.example",
      sourceSeparated: true,
      selfIps: [],
    };
    await assert.rejects(
      () => fetchInteractions(config, "secret-run-token-0123456789"),
      (err: Error) => {
        assert.match(err.message, /OOB oracle unreachable \(https:\/\/oracle.example\)/);
        assert.ok(!err.message.includes("token="), "run token must not appear in errors");
        assert.ok(!err.message.includes("secret-run-token"), "run token value must not leak");
        return true;
      },
    );
  });

  it("redacts the request URL when the underlying error echoes it", async () => {
    // Some runtimes embed the full request URL (query included) in fetch
    // failures — the sanitizer must strip it before the message escapes.
    setOobOracleFetchForTest(async (url: string) => {
      throw new TypeError(`fetch failed for ${url}`);
    });
    const config: OobOracleConfig = {
      baseUrl: "https://oracle.example",
      sourceSeparated: true,
      selfIps: [],
    };
    await assert.rejects(
      () => fetchInteractions(config, "leaky-run-token-9876543210"),
      (err: Error) => {
        assert.ok(!err.message.includes("token=leaky-run-token"), "token query must be redacted");
        assert.match(err.message, /\[redacted-(url|path)\]/);
        return true;
      },
    );
  });

  it("provision failures do not echo the URL", async () => {
    setOobOracleFetchForTest(async () => {
      throw new Error("network down");
    });
    const config: OobOracleConfig = {
      baseUrl: "https://oracle.example",
      sourceSeparated: true,
      selfIps: [],
    };
    await assert.rejects(
      () => provisionCallback(config),
      (err: Error) => !err.message.includes("oracle.example/provision"),
    );
  });
});
