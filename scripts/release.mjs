#!/usr/bin/env node

import { execSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync, writeFileSync, statSync } from "node:fs";
import { join } from "node:path";

const RELEASE_TARGET = process.argv[2];
const BUMP_TYPES = new Set(["major", "minor", "patch"]);
const SEMVER_RE = /^\d+\.\d+\.\d+$/;

if (!RELEASE_TARGET || (!BUMP_TYPES.has(RELEASE_TARGET) && !SEMVER_RE.test(RELEASE_TARGET))) {
	console.error("Usage: node scripts/release.mjs <major|minor|patch|x.y.z>");
	process.exit(1);
}

function run(cmd, options = {}) {
	console.log(`$ ${cmd}`);
	try {
		return execSync(cmd, { encoding: "utf-8", stdio: options.silent ? "pipe" : "inherit", ...options });
	} catch (_e) {
		if (!options.ignoreError) {
			console.error(`Command failed: ${cmd}`);
			process.exit(1);
		}
		return null;
	}
}

function getVersion() {
	const pkg = JSON.parse(readFileSync("package.json", "utf-8"));
	return pkg.version;
}

function compareVersions(a, b) {
	const aParts = a.split(".").map(Number);
	const bParts = b.split(".").map(Number);
	for (let i = 0; i < 3; i++) {
		const diff = (aParts[i] || 0) - (bParts[i] || 0);
		if (diff !== 0) return diff;
	}
	return 0;
}

function shellQuote(value) {
	return `'${value.replace(/'/g, `'\\''`)}'`;
}

function stageChangedFiles() {
	const output = run("git ls-files -m -o -d --exclude-standard", { silent: true });
	const paths = [
		...new Set(
			(output || "")
				.split("\n")
				.map((line) => line.trim())
				.filter(Boolean),
		),
	];
	if (paths.length === 0) return;
	run(`git add -- ${paths.map(shellQuote).join(" ")}`);
}

function commitIfStaged(message) {
	try {
		execSync("git diff --cached --quiet");
		console.log("  No changes staged to commit.");
	} catch {
		run(`git commit -m "${message}"`);
	}
}

function bumpOrSetVersion(target) {
	const currentVersion = getVersion();
	let newVersion;

	if (BUMP_TYPES.has(target)) {
		const parts = currentVersion.split(".").map(Number);
		if (target === "major") {
			parts[0] += 1;
			parts[1] = 0;
			parts[2] = 0;
		} else if (target === "minor") {
			parts[1] += 1;
			parts[2] = 0;
		} else if (target === "patch") {
			parts[2] += 1;
		}
		newVersion = parts.join(".");
		console.log(`Bumping version (${target}) to v${newVersion}...`);
	} else {
		if (compareVersions(target, currentVersion) <= 0) {
			console.error(`Error: explicit version ${target} must be greater than current version ${currentVersion}.`);
			process.exit(1);
		}
		newVersion = target;
		console.log(`Setting explicit version to v${newVersion}...`);
	}

	const packagesDir = "packages";
	const packages = readdirSync(packagesDir).filter((name) => {
		try {
			return statSync(join(packagesDir, name)).isDirectory();
		} catch {
			return false;
		}
	});

	const targetPaths = [
		"package.json",
		...packages.map((pkg) => join(packagesDir, pkg, "package.json")),
	];

	for (const pkgPath of targetPaths) {
		if (existsSync(pkgPath)) {
			const data = JSON.parse(readFileSync(pkgPath, "utf-8"));
			data.version = newVersion;
			writeFileSync(pkgPath, JSON.stringify(data, null, 2) + "\n");
			console.log(`  Updated ${pkgPath} to v${newVersion}`);
		}
	}

	run("node scripts/sync-versions.js");
	return newVersion;
}

function getChangelogs() {
	const packagesDir = "packages";
	const packages = readdirSync(packagesDir);
	const changelogs = packages.map((pkg) => join(packagesDir, pkg, "CHANGELOG.md")).filter((path) => existsSync(path));
	if (existsSync("CHANGELOG.md")) changelogs.push("CHANGELOG.md");
	return changelogs;
}

function updateChangelogsForRelease(version) {
	const date = new Date().toISOString().split("T")[0];
	const changelogs = getChangelogs();
	for (const changelog of changelogs) {
		const content = readFileSync(changelog, "utf-8");
		if (!content.includes("## [Unreleased]")) {
			console.log(`  Skipping ${changelog}: no [Unreleased] section`);
			continue;
		}
		const updated = content.replace("## [Unreleased]", `## [${version}] - ${date}`);
		writeFileSync(changelog, updated);
		console.log(`  Updated ${changelog}`);
	}
}

function addUnreleasedSection() {
	const changelogs = getChangelogs();
	const unreleasedSection = "## [Unreleased]\n\n";
	for (const changelog of changelogs) {
		const content = readFileSync(changelog, "utf-8");
		const updated = content.replace(/^(## \[)/m, `${unreleasedSection}$1`);
		writeFileSync(changelog, updated);
		console.log(`  Added [Unreleased] to ${changelog}`);
	}
}

function getUnreleasedBody(changelogPath) {
	const content = readFileSync(changelogPath, "utf-8");
	const start = content.indexOf("## [Unreleased]");
	if (start === -1) return null;
	const after = content.slice(start + "## [Unreleased]".length);
	const nextHeader = after.search(/^## \[/m);
	const body = nextHeader === -1 ? after : after.slice(0, nextHeader);
	return body;
}

function hasUnreleasedEntries() {
	const changelogs = getChangelogs();
	for (const changelog of changelogs) {
		const body = getUnreleasedBody(changelog);
		if (body && /^- /m.test(body)) return true;
	}
	return false;
}

// Main
console.log("\n=== pi-xpi Release ===\n");

console.log("Checking for uncommitted changes...");
const status = run("git status --porcelain", { silent: true });
if (status?.trim()) {
	console.error("Error: Uncommitted changes detected. Commit or stash first.");
	console.error(status);
	process.exit(1);
}
console.log("  Working directory clean\n");

console.log("Running tests...");
run("npm test");
console.log();

console.log("Checking [Unreleased] sections...");
if (!hasUnreleasedEntries()) {
	console.log("  Warning: no [Unreleased] entries found. Proceeding anyway.\n");
}

const version = bumpOrSetVersion(RELEASE_TARGET);
console.log(`  New version: ${version}\n`);

console.log("Promoting CHANGELOG.md [Unreleased] sections...");
updateChangelogsForRelease(version);
console.log();

console.log("Committing and tagging...");
stageChangedFiles();
commitIfStaged(`Release v${version}`);
run(`git tag v${version}`);
console.log();

console.log("Reinstating [Unreleased] sections for next cycle...");
addUnreleasedSection();
console.log();

console.log("Committing changelog updates...");
stageChangedFiles();
commitIfStaged("Add [Unreleased] section for next cycle");
console.log();

console.log("Pushing to remote...");
run("git push origin main");
run(`git push origin v${version}`);
console.log();

console.log(`=== Released v${version} ===`);
