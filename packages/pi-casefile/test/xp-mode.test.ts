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
    expect(readXpMode("on", path)).toBe("on");
    expect(readXpMode("1", path)).toBe("on");
    expect(readXpMode("true", path)).toBe("on");
    writeFileSync(path, "on", "utf8");
    expect(readXpMode("off", path)).toBe("off");
    expect(readXpMode("0", path)).toBe("off");
    expect(readXpMode("false", path)).toBe("off");
  });

  it("reads persisted file when env unset", () => {
    const path = tempStatePath();
    writeXpMode("on", path);
    expect(readFileSync(path, "utf8")).toBe("on");
    expect(readXpMode("", path)).toBe("on");
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
  it("sets on/off explicitly and toggles otherwise", () => {
    expect(parseXpModeArg("on", "off")).toBe("on");
    expect(parseXpModeArg("off", "on")).toBe("off");
    expect(parseXpModeArg("", "off")).toBe("on");
    expect(parseXpModeArg("  ", "on")).toBe("off");
    expect(parseXpModeArg("nope", "off")).toBe("on");
  });
});
