#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const packageDirs = ["pi-shared", "pi-casefile", "pi-webxp", "pi-xtodo"].map((name) =>
  join(root, "packages", name),
);
export const publishDirs = [...packageDirs, root];

function manifest(cwd) {
  return JSON.parse(readFileSync(join(cwd, "package.json"), "utf8"));
}

function runNpm(args, cwd, stdio = "pipe") {
  return spawnSync("npm", args, { cwd, encoding: "utf8", stdio });
}

export function versionAlreadyPublished(name, version, cwd, npm = runNpm) {
  const result = npm(["view", `${name}@${version}`, "version", "--json"], cwd);
  if (result.status === 0) {
    try {
      return JSON.parse(result.stdout.trim()) === version;
    } catch {
      return result.stdout.trim().replace(/^"|"$/g, "") === version;
    }
  }
  const output = `${result.stdout ?? ""}\n${result.stderr ?? ""}`;
  if (/E404|404 Not Found|is not in this registry/i.test(output)) return false;
  throw new Error(`npm view failed for ${name}@${version}: ${output.trim()}`);
}

export function publishAll(npm = runNpm) {
  for (const cwd of publishDirs) {
    const pkg = manifest(cwd);
    if (versionAlreadyPublished(pkg.name, pkg.version, cwd, npm)) {
      process.stdout.write(`skip ${pkg.name}@${pkg.version} (already published)\n`);
      continue;
    }
    process.stdout.write(`publish ${pkg.name}@${pkg.version}\n`);
    const result = npm(["publish", "--access", "public", "--provenance"], cwd, "inherit");
    if (result.status !== 0) return result.status ?? 1;
  }
  return 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = publishAll();
}
