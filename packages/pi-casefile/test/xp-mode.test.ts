import { afterEach, describe, expect, it } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseXpModeArg, readXpMode, writeXpMode } from "../src/index.ts";

const dirs: string[] = [];

afterEach(() => {
  for (const d of dirs.splice(0)) {
    try {
      rmSync(d, { recursive: true, force: true });
    } catch {
      // ignore
    }
  }
});

function tempStatePath(): string {
  const dir = mkdtempSync(join(tmpdir(), "xpi-xp-"));
  dirs.push(dir);
  return join(dir, "xp-mode");
}

describe("readXpMode / writeXpMode", () => {
  it("defaults to off when env and file are absent", () => {
    const path = tempStatePath();
    expect(readXpMode("", path)).toBe("off");
    expect(readXpMode(undefined, path)).toBe("off");
  });

  it("env overrides file", () => {
    const path = tempStatePath();
    writeFileSync(path, "off", "utf8");
    expect(readXpMode("swarm", path)).toBe("swarm");
    expect(readXpMode("on", path)).toBe("swarm");
    expect(readXpMode("1", path)).toBe("swarm");
    expect(readXpMode("true", path)).toBe("swarm");
    writeFileSync(path, "swarm", "utf8");
    expect(readXpMode("off", path)).toBe("off");
    expect(readXpMode("0", path)).toBe("off");
    expect(readXpMode("false", path)).toBe("off");
  });

  it("supports lite mode via env and file", () => {
    const path = tempStatePath();
    expect(readXpMode("lite", path)).toBe("lite");
    // env lite overrides an on/off file
    writeFileSync(path, "on", "utf8");
    expect(readXpMode("lite", path)).toBe("lite");
    // file lite is read when env is unset
    writeXpMode("lite", path);
    expect(readFileSync(path, "utf8")).toBe("lite");
    expect(readXpMode("", path)).toBe("lite");
    // env on is the default enabled mode: swarm
    expect(readXpMode("on", path)).toBe("swarm");
  });

  it("reads persisted file when env unset", () => {
    const path = tempStatePath();
    writeXpMode("swarm", path);
    expect(readFileSync(path, "utf8")).toBe("swarm");
    expect(readXpMode("", path)).toBe("swarm");
    writeFileSync(path, "on", "utf8");
    expect(readXpMode("", path)).toBe("swarm");
    writeXpMode("off", path);
    expect(readXpMode("", path)).toBe("off");
  });

  it("ignores garbage file contents", () => {
    const path = tempStatePath();
    writeFileSync(path, "maybe", "utf8");
    expect(readXpMode("", path)).toBe("off");
  });
});

describe("parseXpModeArg", () => {
  it("sets swarm/off explicitly and bare /xp toggles swarm", () => {
    expect(parseXpModeArg("swarm", "off")).toBe("swarm");
    expect(parseXpModeArg("on", "off")).toBe("swarm");
    expect(parseXpModeArg("off", "swarm")).toBe("off");
    expect(parseXpModeArg("", "off")).toBe("swarm");
    expect(parseXpModeArg("  ", "lite")).toBe("off");
    expect(parseXpModeArg("nope", "off")).toBe("swarm");
  });

  it("accepts lite explicitly and bare /xp toggles any enabled mode off", () => {
    expect(parseXpModeArg("lite", "off")).toBe("lite");
    expect(parseXpModeArg("LITE", "swarm")).toBe("lite");
    expect(parseXpModeArg("lite", "lite")).toBe("lite");
    expect(parseXpModeArg("", "lite")).toBe("off");
    expect(parseXpModeArg("", "swarm")).toBe("off");
  });
});
