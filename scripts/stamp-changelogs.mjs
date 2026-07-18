#!/usr/bin/env node
/**
 * Stamp `## [Unreleased]` sections with the release version + date across the
 * root and every package CHANGELOG.md. Shared by scripts/release.mjs (local
 * releases) and .github/workflows/release.yml (CI releases) so both paths
 * produce identical changelogs.
 *
 * Usage: node scripts/stamp-changelogs.mjs <version>
 */

import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const version = process.argv[2];
if (!version || !/^\d+\.\d+\.\d+$/.test(version)) {
  console.error("usage: node scripts/stamp-changelogs.mjs <semver>");
  process.exit(1);
}

const changelogs = readdirSync("packages")
  .map((pkg) => join("packages", pkg, "CHANGELOG.md"))
  .filter((p) => existsSync(p));
if (existsSync("CHANGELOG.md")) changelogs.push("CHANGELOG.md");

const date = new Date().toISOString().split("T")[0];
let stamped = 0;
for (const path of changelogs) {
  const content = readFileSync(path, "utf-8");
  if (!content.includes("## [Unreleased]")) continue;
  writeFileSync(path, content.replace("## [Unreleased]", `## [${version}] - ${date}`));
  console.log(`stamped ${path}`);
  stamped++;
}
console.log(
  stamped ? `Stamped ${stamped} changelog(s) for v${version}` : "No [Unreleased] sections found",
);
