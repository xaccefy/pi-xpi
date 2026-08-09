#!/usr/bin/env node
// Bump the umbrella package and every workspace to the same version.
// All manifests are parsed and validated before any file is changed.
import { existsSync, readdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const SEMVER_RE = /^\d+\.\d+\.\d+$/;
const bump = process.argv[2] || "patch";
if (!["patch", "minor", "major"].includes(bump) && !SEMVER_RE.test(bump)) {
  throw new Error(`Expected patch, minor, major, or a newer x.y.z version; got "${bump}"`);
}

function nextVersion(version) {
  if (SEMVER_RE.test(bump)) {
    if (bump.localeCompare(version, undefined, { numeric: true, sensitivity: "base" }) <= 0) {
      throw new Error(`Explicit version ${bump} must be newer than ${version}`);
    }
    return bump;
  }

  const match = /^(\d+)\.(\d+)\.(\d+)$/.exec(version);
  if (!match) throw new Error(`Unsupported current version: ${version}`);
  let [major, minor, patch] = [Number(match[1]), Number(match[2]), Number(match[3])];
  if (bump === "major") {
    major++;
    minor = 0;
    patch = 0;
  } else if (bump === "minor") {
    minor++;
    patch = 0;
  } else {
    patch++;
  }
  return `${major}.${minor}.${patch}`;
}

const format = (data) => `${JSON.stringify(data, null, "  ")}\n`;
const rootDir = process.cwd();
const rootPath = join(rootDir, "package.json");
const packagesDir = join(rootDir, "packages");
if (!existsSync(rootPath) || !existsSync(packagesDir)) {
  throw new Error("Run this script from the XPI repository root");
}

const workspacePaths = readdirSync(packagesDir, { withFileTypes: true })
  .filter((entry) => entry.isDirectory())
  .map((entry) => join(packagesDir, entry.name, "package.json"));
const missing = workspacePaths.filter((path) => !existsSync(path));
if (missing.length) throw new Error(`Missing workspace manifest(s): ${missing.join(", ")}`);
const manifestPaths = [rootPath, ...workspacePaths];

const manifests = manifestPaths.map((path) => {
  let data;
  try {
    data = JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    throw new Error(`Cannot parse ${path}: ${error.message}`);
  }
  if (typeof data.name !== "string" || typeof data.version !== "string") {
    throw new Error(`${path} must contain string name and version fields`);
  }
  if (!SEMVER_RE.test(data.version)) {
    throw new Error(`${path} has unsupported version ${data.version}`);
  }
  return { path, data };
});

const current = manifests[0].data.version;
const mismatched = manifests.filter(({ data }) => data.version !== current);
if (mismatched.length) {
  throw new Error(
    `Workspace versions must match root ${current}: ${mismatched
      .map(({ data }) => `${data.name}@${data.version}`)
      .join(", ")}`,
  );
}

const next = nextVersion(current);
const internalNames = new Set(manifests.map(({ data }) => data.name));
for (const { data } of manifests) {
  data.version = next;
  for (const section of ["dependencies", "optionalDependencies"]) {
    const dependencies = data[section];
    if (!dependencies || typeof dependencies !== "object") continue;
    for (const name of Object.keys(dependencies)) {
      if (internalNames.has(name)) dependencies[name] = next;
    }
  }
}

const temporaryPaths = [];
try {
  for (const { path, data } of manifests) {
    const temporary = `${path}.${process.pid}.tmp`;
    writeFileSync(temporary, format(data), "utf8");
    temporaryPaths.push(temporary);
  }
  for (let i = 0; i < manifests.length; i++) {
    renameSync(temporaryPaths[i], manifests[i].path);
  }
} finally {
  for (const temporary of temporaryPaths) rmSync(temporary, { force: true });
}

console.log(`Bumped ${manifests.length} packages: ${current} -> ${next}`);
