#!/usr/bin/env node
// Tarball-import gate: every relative module an extension entrypoint imports
// must be inside the npm tarball `files` produces.
//
// Failure this gate exists for (caught before v0.9.5 shipped): rawhttp.ts,
// jwtx.ts (pi-webxp) and oob-oracle.ts (pi-casefile) were imported by the
// packed index.ts but absent from the package.json `files` allowlist — npm
// users would crash at extension load with module-not-found.
//
// Usage: node scripts/check-pack.js [--ignore-scripts]
// Exit 0 = every import is packed; exit 1 = missing files listed.

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import {
  dirname as posixDirname,
  join as posixJoin,
  normalize as posixNormalize,
} from "node:path/posix";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const workspaceNames = ["pi-shared", "pi-casefile", "pi-webxp", "pi-xtodo"];
const packages = [...workspaceNames.map((n) => join(root, "packages", n)), root];

/** Run `npm pack --dry-run --json` in cwd; return packed paths as REPO-relative set. */
function packedFilesRepoRelative(cwd, pkgPrefix) {
  const extraArgs = process.argv.includes("--ignore-scripts") ? ["--ignore-scripts"] : [];
  const result = spawnSync("npm", ["pack", "--dry-run", "--json", ...extraArgs], {
    cwd,
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.status !== 0) {
    throw new Error(`npm pack failed in ${cwd}: ${result.stderr?.slice(0, 300)}`);
  }
  const parsed = JSON.parse(result.stdout);
  return new Set(parsed[0].files.map((f) => pkgPrefix + f.path.replace(/\\/g, "/")));
}

/** Resolve one relative ./ or ../ specifier from a repo-relative source path. */
function resolveRelativeTarget(fromRel, spec) {
  if (!spec.startsWith(".")) return undefined;
  return posixNormalize(posixJoin(posixDirname(fromRel), spec));
}

/**
 * Transitive relative imports of an entrypoint, within its own package only
 * (cross-package imports are workspace deps npm resolves at install time).
 */
function collectRelativeImports(entryRel, pkgPrefix, seen = new Set()) {
  if (seen.has(entryRel)) return seen;
  seen.add(entryRel);
  let source;
  try {
    source = readFileSync(join(root, entryRel), "utf8");
  } catch {
    return seen;
  }
  // import ... from "./x.ts" | export ... from "../y.ts" | dynamic import("./z.ts")
  const re =
    /(?:^|[\s(}])(?:import|export)[\s\S]*?from\s*["'](\.[^"']+)["']|import\(\s*["'](\.[^"']+)["']\s*\)/g;
  for (const match of source.matchAll(re)) {
    const target = resolveRelativeTarget(entryRel, match[1] ?? match[2]);
    if (!target || !target.startsWith(pkgPrefix)) continue;
    if (!seen.has(target)) collectRelativeImports(target, pkgPrefix, seen);
  }
  return seen;
}

let failures = 0;
for (const pkgDir of packages) {
  const manifest = JSON.parse(readFileSync(join(pkgDir, "package.json"), "utf8"));
  const pkgPrefix = `${join(pkgDir, "/")
    .slice(root.length + 1)
    .replace(/\\/g, "/")}`;
  const packed = packedFilesRepoRelative(pkgDir, pkgPrefix);

  for (const ext of manifest.pi?.extensions ?? []) {
    const entryRel = posixNormalize(`${pkgPrefix}${ext.replace(/^\.\//, "")}`);
    if (!packed.has(entryRel)) {
      console.error(`MISSING ENTRYPOINT ${manifest.name}: ${entryRel} is not in the npm tarball`);
      failures++;
    }
    for (const rel of collectRelativeImports(entryRel, pkgPrefix)) {
      if (!packed.has(rel)) {
        console.error(
          `MISSING IMPORT ${manifest.name}: ${entryRel} transitively imports ${rel} which npm pack excludes`,
        );
        failures++;
      }
    }
  }
}

if (failures > 0) {
  console.error(`\ncheck-pack: ${failures} file(s) imported but excluded from the tarball.`);
  console.error("Add them to the package.json `files` array, then re-run.");
  process.exit(1);
}
console.log("check-pack: all extension entrypoints and their transitive imports are packed.");
