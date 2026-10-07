import assert from "node:assert";
import { spawnSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const validator = join(root, "scripts", "validate-records.js");
const fixturesDir = join(root, "test", "fixtures", "records");

/**
 * Producer-compatible fixture tests for scripts/validate-records.js and the
 * schemas/ record contracts. Valid fixtures must pass; invalid-* fixtures
 * must fail with a diagnostic naming the offending field. Format validation
 * only — a passing fixture says nothing about whether a finding is true.
 */
function runValidator(args) {
  return spawnSync(process.execPath, [validator, ...args], { encoding: "utf8" });
}

describe("record validator fixtures", () => {
  const fixtures = readdirSync(fixturesDir).filter((f) => f.endsWith(".json"));

  it("fixture directory is populated with both valid and invalid records", () => {
    assert.ok(fixtures.length >= 8, "expected the full fixture set");
    assert.ok(fixtures.some((f) => f.startsWith("invalid-")), "expected invalid-* fixtures");
    assert.ok(fixtures.filter((f) => !f.startsWith("invalid-")).length >= 5, "expected valid fixtures");
  });

  for (const fixture of fixtures) {
    const shouldFail = fixture.startsWith("invalid-");
    it(`${shouldFail ? "rejects" : "accepts"} ${fixture}`, () => {
      const result = runValidator([join(fixturesDir, fixture)]);
      if (shouldFail) {
        assert.notStrictEqual(result.status, 0, `validator accepted an invalid record:\n${result.stdout}`);
        assert.ok(result.stderr.trim().length > 0, "invalid records must print diagnostics");
      } else {
        assert.strictEqual(
          result.status,
          0,
          `validator rejected a valid record:\n${result.stderr}`,
        );
      }
    });
  }

  it("every valid fixture is well-formed JSON parsed by the validator itself", () => {
    for (const fixture of fixtures.filter((f) => !f.startsWith("invalid-"))) {
      const doc = JSON.parse(readFileSync(join(fixturesDir, fixture), "utf8"));
      assert.match(doc.schema, /^xpi\/(audit-run|coverage-ledger|finding-record)@1$/);
    }
  });

  it("--type rejects a record of the wrong type", () => {
    const result = runValidator([
      join(fixturesDir, "finding-rejected.json"),
      "--type",
      "manifest",
    ]);
    assert.notStrictEqual(result.status, 0);
    assert.match(result.stderr, /expected xpi\/audit-run@1/);
  });

  it("malformed JSON fails with a parse error", () => {
    const result = runValidator([join(fixturesDir, "invalid-not-json.json")]);
    assert.strictEqual(result.status, 1);
    assert.match(result.stderr, /invalid JSON/);
  });

  it("--all cross-validates finding coverageUnits against a same-runId ledger", () => {
    const bad = runValidator(["--all", join(fixturesDir, "linkage")]);
    assert.strictEqual(bad.status, 1, `expected linkage failure:\n${bad.stderr}`);
    assert.match(bad.stderr, /not present in .*ledger\.json/);
    assert.match(bad.stderr, /src\/missing\/unit\.ts:none:ghost/);

    const good = runValidator(["--all", join(fixturesDir, "linkage-ok")]);
    assert.strictEqual(good.status, 0, good.stderr);
  });

  it("--all reports linkage UNCHECKED when no ledger shares the finding's runId", () => {
    // Different runIds: the finding references a unit its batch's ledger does
    // not know, but no ledger shares the finding's runId, so linkage is
    // reported as explicitly UNCHECKED — never silently accepted, never a
    // failure either.
    const result = runValidator(["--all", join(fixturesDir, "linkage-partial")]);
    assert.strictEqual(result.status, 0, result.stderr);
    assert.match(result.stderr, /linkage UNCHECKED/);
    assert.match(result.stderr, /no coverage ledger with runId audit-link-2025-0002/);
    assert.ok(!result.stderr.includes("not present in"));
  });

  it("rejects a non-array confirmed.sourceTrace", () => {
    const result = runValidator([join(fixturesDir, "invalid-finding-non-array-sourcetrace.json")]);
    assert.strictEqual(result.status, 1);
    assert.match(result.stderr, /sourceTrace/);
    assert.match(result.stderr, /must be an array/);
  });

  it("rejects records carrying more than one disposition payload", () => {
    const result = runValidator([join(fixturesDir, "invalid-finding-mixed-payloads.json")]);
    assert.strictEqual(result.status, 1);
    assert.match(result.stderr, /mutually exclusive/);
  });

  it("rejects wrong-typed optional fields the schemas constrain", () => {
    const exclude = runValidator([join(fixturesDir, "invalid-manifest-non-array-exclude.json")]);
    assert.match(exclude.stderr, /scope\.exclude/);
    assert.match(exclude.stderr, /must be an array of paths/);

    const prior = runValidator([join(fixturesDir, "invalid-manifest-non-array-priorruns.json")]);
    assert.match(prior.stderr, /priorRuns/);
    assert.match(prior.stderr, /must be an array of prior-run entries/);

    const paths = runValidator([join(fixturesDir, "invalid-ledger-non-array-reviewedpaths.json")]);
    assert.match(paths.stderr, /reviewedPaths/);
    assert.match(paths.stderr, /must be an array of repo-relative paths/);
  });

  it("rejects a JSON null document without crashing", () => {
    const result = runValidator([join(fixturesDir, "invalid-null-document.json")]);
    assert.strictEqual(result.status, 1);
    assert.match(result.stderr, /document must be a JSON object/);
  });

  it("--type on a JSON null document reports an invalid record, not a crash", () => {
    // The --type fast path used to read doc.schema before the null guard.
    for (const type of ["manifest", "ledger", "finding"]) {
      const result = runValidator([join(fixturesDir, "invalid-null-document.json"), "--type", type]);
      assert.strictEqual(result.status, 1, `--type ${type} must exit 1`);
      assert.match(result.stderr, /document must be a JSON object/);
    }
  });

  it("rejects unknown fields inside nested evidence items", () => {
    const result = runValidator([join(fixturesDir, "invalid-finding-evidence-extra-field.json")]);
    assert.strictEqual(result.status, 1);
    assert.match(result.stderr, /unknown field/);
    assert.match(result.stderr, /evidence\[0\]\.note/);
  });

  it("rejects non-string members in confirmed.conditions and non-string roles.provider", () => {
    const cond = runValidator([join(fixturesDir, "invalid-finding-non-string-condition.json")]);
    assert.strictEqual(cond.status, 1);
    assert.match(cond.stderr, /conditions\[1\]/);
    assert.match(cond.stderr, /non-empty string/);

    const provider = runValidator([join(fixturesDir, "invalid-manifest-bad-provider.json")]);
    assert.strictEqual(provider.status, 1);
    assert.match(provider.stderr, /roles\.auditor\.provider/);
    assert.match(provider.stderr, /provider must be a string when present/);
  });

  it("unit tests: duplicate ledger ids, bare covered units, missing verifier are each named", () => {
    const dupe = runValidator([join(fixturesDir, "invalid-ledger-dupe-id.json")]);
    assert.match(dupe.stderr, /duplicate unit id/);
    const bare = runValidator([join(fixturesDir, "invalid-ledger-covered-no-evidence.json")]);
    assert.match(bare.stderr, /reviewed path/);
    assert.match(bare.stderr, /evidence-backed check/);
    const noVerifier = runValidator([
      join(fixturesDir, "invalid-finding-confirmed-no-verifier.json"),
    ]);
    assert.match(noVerifier.stderr, /verifiedBy/);
  });
});
