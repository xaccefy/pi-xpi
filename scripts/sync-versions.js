#!/usr/bin/env node
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const packagesDir = join(process.cwd(), "packages");
const packageDirs = readdirSync(packagesDir, { withFileTypes: true })
  .filter((dirent) => dirent.isDirectory())
  .map((dirent) => dirent.name);

const packages = {};
const versionMap = {};

for (const dir of packageDirs) {
  const pkgPath = join(packagesDir, dir, "package.json");
  try {
    const pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
    packages[dir] = { path: pkgPath, data: pkg };
    versionMap[pkg.name] = pkg.version;
  } catch (_e) {}
}

// Also read root
const rootPkgPath = join(process.cwd(), "package.json");
const rootPkg = JSON.parse(readFileSync(rootPkgPath, "utf8"));
versionMap[rootPkg.name] = rootPkg.version;

const versions = new Set(Object.values(versionMap));
if (versions.size > 1) {
  console.error(
    `error: version mismatch across workspace packages: ${JSON.stringify(versionMap, null, 2)}`,
  );
  process.exit(1);
}

for (const [, pkg] of Object.entries(packages)) {
  let updated = false;

  if (pkg.data.dependencies) {
    for (const [depName, currentVersion] of Object.entries(pkg.data.dependencies)) {
      if (versionMap[depName]) {
        const newVersion = `^${versionMap[depName]}`;
        if (currentVersion !== newVersion) {
          pkg.data.dependencies[depName] = newVersion;
          updated = true;
        }
      }
    }
  }

  if (pkg.data.devDependencies) {
    for (const [depName, currentVersion] of Object.entries(pkg.data.devDependencies)) {
      if (versionMap[depName]) {
        const newVersion = `^${versionMap[depName]}`;
        if (currentVersion !== newVersion) {
          pkg.data.devDependencies[depName] = newVersion;
          updated = true;
        }
      }
    }
  }

  if (updated) {
    writeFileSync(pkg.path, `${JSON.stringify(pkg.data, null, "  ")}\n`);
  }
}
