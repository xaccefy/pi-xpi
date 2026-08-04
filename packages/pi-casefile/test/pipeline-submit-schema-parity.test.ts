/**
 * Drift guard: schemas/*.json (agent-facing contract) and the SPECS table in
 * pipeline-submit.ts (executable gate) are hand-mirrored. This test pins the
 * parts agents depend on — required field sets and enum values — so the two
 * cannot silently diverge. Conditionals (allOf) are prose-compared in review;
 * the locator XOR for hunt is pinned separately below.
 */
import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { SPECS, type SubmitStage } from "../src/pipeline-submit.ts";

const SCHEMAS_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "schemas");

const STAGE_TO_SCHEMA: Record<SubmitStage, string> = {
  hunt: "stage-finding.json",
  trace: "stage-trace.json",
  skeptic: "stage-skeptic.json",
  validate: "stage-validation.json",
  chain: "stage-chain.json",
  report: "stage-report.json",
};

function loadSchema(stage: SubmitStage): {
  required?: string[];
  properties?: Record<string, { enum?: string[] }>;
  oneOf?: { required?: string[] }[];
  allOf?: {
    if?: { properties?: Record<string, { const?: string }> };
    then?: { required?: string[] };
  }[];
} {
  return JSON.parse(readFileSync(join(SCHEMAS_DIR, STAGE_TO_SCHEMA[stage]), "utf8"));
}

describe("pipeline_submit > schemas/*.json parity with SPECS", () => {
  for (const stage of Object.keys(SPECS) as SubmitStage[]) {
    it(`${stage} (${STAGE_TO_SCHEMA[stage]}): required field set matches`, () => {
      const schema = loadSchema(stage);
      expect((schema.required ?? []).sort()).toEqual(
        SPECS[stage].required.map((f) => f.name).sort(),
      );
    });

    it(`${stage} (${STAGE_TO_SCHEMA[stage]}): enum values match per field`, () => {
      const schema = loadSchema(stage);
      for (const field of SPECS[stage].required) {
        if (!field.enum) continue;
        const schemaEnum = schema.properties?.[field.name]?.enum;
        expect(
          schemaEnum,
          `field "${field.name}" has an enum in SPECS but not in the JSON schema`,
        ).toBeDefined();
        expect([...(schemaEnum ?? [])].sort()).toEqual([...field.enum].sort());
      }
    });
  }

  it("hunt locator XOR: JSON schema encodes exactly file+line OR endpoint", () => {
    const schema = loadSchema("hunt");
    // Structural pin: the runtime locatorXor demands EXACTLY ONE of the two
    // locator sets. JSON Schema's `oneOf` (not `anyOf`) carries that semantic
    // — with anyOf, file+line+endpoint passes the doc contract but the gate
    // rejects it. Two branches, pinned sets.
    expect(schema.oneOf).toHaveLength(2);
    expect(schema.oneOf?.map((b) => (b.required ?? []).sort()).sort()).toEqual([
      ["endpoint"],
      ["file", "line"],
    ]);
  });

  it("stages with conditionals: JSON allOf mirrors SPECS.conditional", () => {
    for (const stage of Object.keys(SPECS) as SubmitStage[]) {
      const conditional = SPECS[stage].conditional ?? [];
      const allOf = loadSchema(stage).allOf ?? [];
      expect(
        allOf,
        `SPECS has ${conditional.length} conditional(s) but the JSON schema has ${allOf.length} allOf clauses`,
      ).toHaveLength(conditional.length);
      for (const c of conditional) {
        const clause = allOf.find((a) => a.if?.properties?.[c.when.field]?.const === c.when.equals);
        expect(
          clause,
          `no allOf clause for ${c.when.field}=${c.when.equals} in ${STAGE_TO_SCHEMA[stage]}`,
        ).toBeDefined();
        expect([...(clause?.then?.required ?? [])].sort()).toEqual([...c.require].sort());
      }
    }
  });
});
