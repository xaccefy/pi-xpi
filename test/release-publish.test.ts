import assert from "node:assert";
import { describe, it } from "node:test";

import { publishAll, publishDirs, versionAlreadyPublished } from "../scripts/publish-all.js";

type NpmResult = { status: number | null; stdout?: string; stderr?: string };

describe("release publisher", () => {
  it("skips an existing version and publishes missing packages with provenance", () => {
    const calls: { args: string[]; cwd: string; stdio?: string }[] = [];
    const npm = (args: string[], cwd: string, stdio?: string): NpmResult => {
      calls.push({ args, cwd, stdio });
      if (args[0] === "view") {
        const requestedVersion = args[1].slice(args[1].lastIndexOf("@") + 1);
        return args[1].startsWith("@xaccefy/pi-shared@")
          ? { status: 0, stdout: `${JSON.stringify(requestedVersion)}\n`, stderr: "" }
          : { status: 1, stdout: "", stderr: "npm error code E404" };
      }
      return { status: 0, stdout: "", stderr: "" };
    };

    assert.strictEqual(publishAll(npm), 0);
    const publishes = calls.filter((call) => call.args[0] === "publish");
    assert.strictEqual(publishes.length, publishDirs.length - 1);
    for (const call of publishes) {
      assert.deepStrictEqual(call.args, ["publish", "--access", "public", "--provenance"]);
      assert.strictEqual(call.stdio, "inherit");
    }
    assert.ok(
      !publishes.some((call) => call.cwd.endsWith("/packages/pi-shared")),
      "already-published workspace is skipped",
    );
  });

  it("does not treat registry or authentication failures as a missing version", () => {
    assert.throws(
      () =>
        versionAlreadyPublished("@xaccefy/pi-shared", "0.9.0", publishDirs[0], () => ({
          status: 1,
          stdout: "",
          stderr: "npm error code E401 unauthorized",
        })),
      /npm view failed.*E401/,
    );
  });
});
