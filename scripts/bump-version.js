#!/usr/bin/env node
// Bump the umbrella package and every workspace to the next <patch|minor|major>.
//
// We avoid `npm version` on purpose: npm's dependency reconciliation crashes on
// "*" peerDependencies with "Cannot read properties of null (reading 'matches')",
// which broke the release on newer npm. A plain file write is deterministic and
// never reconciles deps.
import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const SEMVER_RE = /^\d+\.\d+\.\d+$/;
const bump = process.argv[2] || "patch";
if (!["patch", "minor", "major"].includes(bump) && !SEMVER_RE.test(bump)) {
  process.exit(1);
}

function nextVersion(v) {
  if (SEMVER_RE.test(bump)) {
    if (bump.localeCompare(v, undefined, { numeric: true, sensitivity: "base" }) <= 0) {
      process.exit(1);
    }
    return bump;
  }
  const m = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$/.exec(v);
  if (!m) {
    process.exit(1);
  }
  let [maj, min, pat] = [Number(m[1]), Number(m[2]), Number(m[3])];
  if (bump === "major") {
    maj++;
    min = 0;
    pat = 0;
  } else if (bump === "minor") {
    min++;
    pat = 0;
  } else {
    pat++;
  }
  return `${maj}.${min}.${pat}`;
}

const FORMAT = (data) => `${JSON.stringify(data, null, "  ")}\n`;

const rootPath = join(process.cwd(), "package.json");
const root = JSON.parse(readFileSync(rootPath, "utf8"));
const next = nextVersion(root.version);
root.version = next;
writeFileSync(rootPath, FORMAT(root));

const pkgsDir = join(process.cwd(), "packages");
if (existsSync(pkgsDir)) {
  for (const d of readdirSync(pkgsDir, { withFileTypes: true })) {
    if (!d.isDirectory()) continue;
    const pkgPath = join(pkgsDir, d.name, "package.json");
    if (!existsSync(pkgPath)) continue;
    try {
      const pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
      pkg.version = next;
      writeFileSync(pkgPath, FORMAT(pkg));
    } catch (_e) {}
  }
}
