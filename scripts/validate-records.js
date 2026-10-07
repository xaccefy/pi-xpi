#!/usr/bin/env node
/**
 * XPI record validator — shape and linkage checks for the three record
 * contracts in schemas/:
 *   - audit-run.schema.json      (run manifest)
 *   - coverage-ledger.schema.json (per-run coverage ledger)
 *   - finding-record.schema.json  (final finding disposition)
 *
 * Dependency-free on purpose (node:stdlib only) so it runs in CI and in a
 * sandbox with no node_modules. It enforces the schemas' structural rules
 * (required + unknown fields, enums, patterns, RFC3339 date-time vs date
 * formats, integer ranges) and cross-field rules (mode/network/authorization,
 * coverage evidence, verifier provenance); the schemas remain the normative
 * contract.
 *
 * Cross-file linkage (--all): finding coverageUnits are checked against a
 * coverage ledger sharing the finding's runId within the same batch. A
 * finding whose runId has no ledger in the batch is reported on stderr as
 * linkage UNCHECKED — absence of a ledger never counts as verified linkage
 * and does not by itself fail the batch.
 *
 * Validator success establishes FORMAT ONLY — never that a finding is true.
 *
 * Usage:
 *   node scripts/validate-records.js <file.json> [--type manifest|ledger|finding]
 *   node scripts/validate-records.js --all <dir>      # validate every .json in dir
 * Exit code 0 = valid, 1 = invalid (errors printed), 2 = usage/IO error.
 */

import { readdirSync, readFileSync, realpathSync } from "node:fs";
import { join } from "node:path";

const HEX16 = /^[a-f0-9]{16}$/;
const RUN_ID = /^[a-z0-9][a-z0-9-]{5,63}$/;
const ISO_DATE_ONLY = /^\d{4}-\d{2}-\d{2}$/;
const ISO_DATE_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;
const ROLE_KEY = /^[a-z][a-z0-9_-]*$/;
const UNIT_ID = /^[a-z0-9][a-z0-9./:_-]{2,127}$/;
const EXPECTED_TYPE = {
  manifest: "xpi/audit-run@1",
  ledger: "xpi/coverage-ledger@1",
  finding: "xpi/finding-record@1",
};

class Errors {
  constructor() {
    this.list = [];
  }
  at(path, message) {
    this.list.push(`${path}: ${message}`);
  }
  check(path, condition, message) {
    if (!condition) this.at(path, message);
    return condition;
  }
  get ok() {
    return this.list.length === 0;
  }
}

function isObject(v) {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function rejectUnknown(err, obj, path, allowed) {
  if (!isObject(obj)) return;
  for (const key of Object.keys(obj)) {
    if (!allowed.includes(key)) err.at(`${path}.${key}`, `unknown field (allowed: ${allowed.join(", ")})`);
  }
}

function requireFields(err, obj, path, required) {
  for (const key of required) {
    if (!(key in obj)) err.at(`${path}.${key}`, "required field missing");
  }
}

/** Date-only (schema `format: date`), e.g. authorization.validUntil. */
function isDateOnly(value) {
  return (
    typeof value === "string" &&
    ISO_DATE_ONLY.test(value) &&
    !Number.isNaN(Date.parse(`${value}T00:00:00Z`))
  );
}

/** RFC3339 date-time (schema `format: date-time`): requires T and a zone. */
function isDateTime(value) {
  return typeof value === "string" && ISO_DATE_TIME.test(value) && !Number.isNaN(Date.parse(value));
}

function validateManifest(doc, err, root) {
  const allowed = [
    "schema", "runId", "created", "ended", "status", "mode", "profile", "harness",
    "target", "scope", "roles", "toolVersions", "budget", "priorRuns", "executionPolicy",
  ];
  rejectUnknown(err, doc, root, allowed);
  requireFields(err, doc, root, [
    "schema", "runId", "created", "mode", "profile", "harness", "target", "scope", "executionPolicy", "status",
  ]);
  err.check(`${root}.schema`, doc.schema === "xpi/audit-run@1", 'must be "xpi/audit-run@1"');
  err.check(`${root}.runId`, RUN_ID.test(String(doc.runId ?? "")), "must match ^[a-z0-9][a-z0-9-]{5,63}$");
  err.check(`${root}.created`, isDateTime(doc.created), "must be an RFC3339 date-time (YYYY-MM-DDTHH:MM:SSZ or with offset)");
  if ("ended" in doc) err.check(`${root}.ended`, isDateTime(doc.ended), "must be an RFC3339 date-time (YYYY-MM-DDTHH:MM:SSZ or with offset)");
  err.check(`${root}.status`, ["running", "completed", "aborted"].includes(doc.status), "invalid status enum");
  err.check(`${root}.mode`, ["source_audit", "authorized_live"].includes(doc.mode), "invalid mode enum");
  err.check(`${root}.profile`, ["quick", "standard", "deep"].includes(doc.profile), "invalid profile enum");
  err.check(`${root}.harness`, ["pi", "omp"].includes(doc.harness), "invalid harness enum");

  const target = doc.target;
  if (err.check(`${root}.target`, isObject(target), "must be an object")) {
    rejectUnknown(err, target, `${root}.target`, ["kind", "reference", "revision", "dirty", "dirtyFiles"]);
    requireFields(err, target, `${root}.target`, ["kind", "reference"]);
    err.check(`${root}.target.kind`, ["repository", "live_service"].includes(target.kind), "invalid target.kind");
    err.check(`${root}.target.reference`, typeof target.reference === "string" && target.reference.length > 0, "must be a non-empty string");
    if ("revision" in target) {
      err.check(`${root}.target.revision`, typeof target.revision === "string", "must be a string");
    }
    if ("dirty" in target) {
      err.check(`${root}.target.dirty`, typeof target.dirty === "boolean", "must be a boolean");
    }
    if ("dirtyFiles" in target) {
      err.check(
        `${root}.target.dirtyFiles`,
        Array.isArray(target.dirtyFiles) && target.dirtyFiles.every((f) => typeof f === "string" && f.length > 0),
        "must be an array of non-empty path strings",
      );
    }
  }

  const scope = doc.scope;
  if (err.check(`${root}.scope`, isObject(scope), "must be an object")) {
    rejectUnknown(err, scope, `${root}.scope`, ["include", "exclude", "authorization"]);
    if (err.check(`${root}.scope.include`, Array.isArray(scope.include) && scope.include.length >= 1, "must be a non-empty array of paths")) {
      for (const [i, inc] of scope.include.entries()) {
        err.check(`${root}.scope.include[${i}]`, typeof inc === "string" && inc.length > 0 && !inc.includes(".."), "must be a non-empty repo-relative path without '..'");
      }
    }
    if ("exclude" in scope) {
      err.check(`${root}.scope.exclude`, Array.isArray(scope.exclude), "must be an array of paths");
      if (Array.isArray(scope.exclude)) {
        for (const [i, exc] of scope.exclude.entries()) {
          err.check(`${root}.scope.exclude[${i}]`, typeof exc === "string" && exc.length > 0, "must be a non-empty path");
        }
      }
    }
    // Mode rules.
    if (doc.mode === "authorized_live") {
      const auth = scope.authorization;
      if (err.check(`${root}.scope.authorization`, isObject(auth), "authorized_live requires an authorization record")) {
        rejectUnknown(err, auth, `${root}.scope.authorization`, ["reference", "operator", "validUntil"]);
        requireFields(err, auth, `${root}.scope.authorization`, ["reference", "operator"]);
        err.check(`${root}.scope.authorization.reference`, typeof auth.reference === "string" && auth.reference.length > 0, "must be a non-empty engagement/program reference");
        err.check(`${root}.scope.authorization.operator`, typeof auth.operator === "string" && auth.operator.length > 0, "must name the authorizing principal");
        if ("validUntil" in auth) {
          err.check(`${root}.scope.authorization.validUntil`, isDateOnly(auth.validUntil), "must be an ISO date (YYYY-MM-DD)");
        }
      }
    }
  }

  const policy = doc.executionPolicy;
  if (err.check(`${root}.executionPolicy`, isObject(policy), "must be an object")) {
    rejectUnknown(err, policy, `${root}.executionPolicy`, ["network", "sandbox", "sandboxFailClosed", "notes"]);
    requireFields(err, policy, `${root}.executionPolicy`, ["network"]);
    err.check(`${root}.executionPolicy.network`, ["none", "loopback", "target"].includes(policy.network), "invalid network enum");
    if (doc.mode === "source_audit") {
      err.check(`${root}.executionPolicy.network`, ["none", "loopback"].includes(policy.network), "source_audit cannot use target network");
    }
    if (doc.mode === "authorized_live" && policy.network === "target") {
      err.check(`${root}.scope.authorization`, isObject(scope && scope.authorization), "network 'target' requires an authorization record");
    }
    if ("sandbox" in policy) {
      err.check(`${root}.executionPolicy.sandbox`, ["docker", "none", "operator-host"].includes(policy.sandbox), "invalid sandbox enum");
      if (policy.sandbox === "operator-host") {
        err.check(`${root}.executionPolicy.sandboxFailClosed`, policy.sandboxFailClosed === true, "operator-host sandbox must still record sandboxFailClosed: true (host opt-in never disables the closed-failure default)");
      }
    }
    if ("sandboxFailClosed" in policy && policy.sandboxFailClosed !== true) {
      err.at(`${root}.executionPolicy.sandboxFailClosed`, "must be true when present — the closed-failure default cannot be recorded as disabled");
    }
    if ("notes" in policy) {
      err.check(`${root}.executionPolicy.notes`, typeof policy.notes === "string", "must be a string");
    }
  }

  if (doc.roles !== undefined) {
    err.check(`${root}.roles`, isObject(doc.roles), "must be an object of role -> {model, provider}");
    for (const [role, cfg] of Object.entries(doc.roles ?? {})) {
      const p = `${root}.roles.${role}`;
      err.check(p, ROLE_KEY.test(role), "role key must match ^[a-z][a-z0-9_-]*$");
      if (err.check(p, isObject(cfg) && typeof cfg.model === "string" && cfg.model.length > 0, "each role needs at least a model")) {
        rejectUnknown(err, cfg, p, ["model", "provider"]);
        if ("provider" in cfg) {
          err.check(`${p}.provider`, typeof cfg.provider === "string", "provider must be a string when present");
        }
      }
    }
  }

  if (doc.toolVersions !== undefined) {
    const p = `${root}.toolVersions`;
    err.check(p, isObject(doc.toolVersions), "must be an object of name -> version string");
    for (const [name, version] of Object.entries(doc.toolVersions ?? {})) {
      err.check(`${p}.${name}`, typeof version === "string" && version.length > 0, "version values must be non-empty strings");
    }
  }

  if (doc.budget !== undefined) {
    const b = doc.budget;
    const p = `${root}.budget`;
    if (err.check(p, isObject(b), "must be an object")) {
      rejectUnknown(err, b, p, [
        "wallClockMinutes",
        "modelCalls",
        "reservedForCoverageReviewPercent",
        "reservedForVerificationPercent",
        "notes",
      ]);
      for (const field of ["wallClockMinutes", "modelCalls"]) {
        if (field in b) {
          err.check(`${p}.${field}`, Number.isInteger(b[field]) && b[field] >= 1, "must be an integer >= 1");
        }
      }
      for (const field of ["reservedForCoverageReviewPercent", "reservedForVerificationPercent"]) {
        if (field in b) {
          err.check(`${p}.${field}`, Number.isInteger(b[field]) && b[field] >= 0 && b[field] <= 90, "must be an integer between 0 and 90");
        }
      }
      if ("notes" in b) {
        err.check(`${p}.notes`, typeof b.notes === "string", "must be a string");
      }
    }
  }

  if (doc.priorRuns !== undefined) {
    err.check(`${root}.priorRuns`, Array.isArray(doc.priorRuns), "must be an array of prior-run entries");
  }
  if (Array.isArray(doc.priorRuns)) {
    for (const [i, prior] of doc.priorRuns.entries()) {
      const p = `${root}.priorRuns[${i}]`;
      if (!isObject(prior)) {
        err.at(p, "must be an object");
        continue;
      }
      rejectUnknown(err, prior, p, ["runId", "disposition", "note"]);
      err.check(`${p}.runId`, RUN_ID.test(String(prior.runId ?? "")), "must match ^[a-z0-9][a-z0-9-]{5,63}$");
      err.check(`${p}.disposition`, ["revalidated", "carried_forward", "superseded"].includes(prior.disposition), "invalid prior-run disposition");
      if ("note" in prior) {
        err.check(`${p}.note`, typeof prior.note === "string", "must be a string");
      }
    }
  }

  if (doc.status === "completed") {
    err.check(`${root}.ended`, "ended" in doc, "completed runs must record an end time");
  }
}

const UNIT_STATUSES = ["planned", "in_progress", "covered", "candidate", "blocked", "deferred", "not_applicable", "out_of_scope"];

function validateLedger(doc, err, root) {
  rejectUnknown(err, doc, root, ["schema", "runId", "units"]);
  requireFields(err, doc, root, ["schema", "runId", "units"]);
  err.check(`${root}.schema`, doc.schema === "xpi/coverage-ledger@1", 'must be "xpi/coverage-ledger@1"');
  err.check(`${root}.runId`, RUN_ID.test(String(doc.runId ?? "")), "must match ^[a-z0-9][a-z0-9-]{5,63}$");
  if (!err.check(`${root}.units`, Array.isArray(doc.units) && doc.units.length >= 1, "must be a non-empty array")) return;

  const seen = new Map();
  for (const [i, unit] of doc.units.entries()) {
    const p = `${root}.units[${i}]`;
    if (!err.check(p, isObject(unit), "must be an object")) continue;
    rejectUnknown(err, unit, p, ["id", "kind", "description", "status", "reviewedPaths", "checks", "findings", "reason", "revisitWhen", "sourceRevision"]);
    requireFields(err, unit, p, ["id", "kind", "description", "status"]);
    err.check(`${p}.id`, typeof unit.id === "string" && UNIT_ID.test(unit.id), "must be a stable unit id (e.g. src/api/upload.ts:unauth:file-upload)");
    if (unit.id !== undefined) {
      if (seen.has(unit.id)) err.at(`${p}.id`, `duplicate unit id (first at units[${seen.get(unit.id)}])`);
      else seen.set(unit.id, i);
    }
    err.check(`${p}.kind`, ["surface", "trust_boundary", "attack_class", "lifecycle_path", "exclusion", "dependency"].includes(unit.kind), "invalid unit kind");
    err.check(`${p}.description`, typeof unit.description === "string" && unit.description.length > 0, "must be a non-empty string");
    err.check(`${p}.status`, UNIT_STATUSES.includes(unit.status), `invalid status (allowed: ${UNIT_STATUSES.join(", ")})`);

    if ("reviewedPaths" in unit) {
      err.check(`${p}.reviewedPaths`, Array.isArray(unit.reviewedPaths), "must be an array of repo-relative paths");
      if (Array.isArray(unit.reviewedPaths)) {
        for (const [j, path] of unit.reviewedPaths.entries()) {
          err.check(`${p}.reviewedPaths[${j}]`, typeof path === "string" && path.length > 0 && !path.startsWith("/") && !path.includes(".."), "must be repo-relative without '..' or leading '/'");
        }
      }
    }
    if ("findings" in unit) {
      err.check(`${p}.findings`, Array.isArray(unit.findings), "must be an array of finding fingerprints");
      if (Array.isArray(unit.findings)) {
        for (const [j, fp] of unit.findings.entries()) {
          err.check(`${p}.findings[${j}]`, HEX16.test(String(fp)), "finding fingerprint must be 16 lowercase hex chars");
        }
      }
    }
    if (unit.checks !== undefined) {
      err.check(`${p}.checks`, Array.isArray(unit.checks), "must be an array");
      if (Array.isArray(unit.checks)) {
        for (const [j, check] of unit.checks.entries()) {
          const cp = `${p}.checks[${j}]`;
          if (!isObject(check)) {
            err.at(cp, "must be an object with kind (case|evidence_item|artifact|tool_call) and ref");
            continue;
          }
          rejectUnknown(err, check, cp, ["kind", "ref"]);
          err.check(`${cp}.kind`, ["case", "evidence_item", "artifact", "tool_call"].includes(check.kind), "invalid check kind");
          err.check(`${cp}.ref`, typeof check.ref === "string" && check.ref.length > 0, "must be a non-empty reference");
        }
      }
    }

    // Status rules — closing a unit demands evidence, never a bare "no finding".
    if (unit.status === "covered" || unit.status === "not_applicable") {
      const paths = Array.isArray(unit.reviewedPaths) ? unit.reviewedPaths.length : 0;
      const checks = Array.isArray(unit.checks) ? unit.checks.length : 0;
      err.check(`${p}.reviewedPaths`, paths >= 1, `${unit.status} requires at least one reviewed path`);
      err.check(`${p}.checks`, checks >= 1, `${unit.status} requires at least one evidence-backed check — "agent found nothing" is not coverage`);
    }
    if (["blocked", "deferred", "out_of_scope", "not_applicable"].includes(unit.status)) {
      err.check(`${p}.reason`, typeof unit.reason === "string" && unit.reason.length > 0, `${unit.status} requires a reason`);
    }
    if (unit.status === "deferred") {
      err.check(`${p}.revisitWhen`, typeof unit.revisitWhen === "string" && unit.revisitWhen.length > 0, "deferred requires a concrete revisit trigger");
    }
    if ("revisitWhen" in unit && unit.status !== "deferred") {
      err.check(`${p}.revisitWhen`, typeof unit.revisitWhen === "string" && unit.revisitWhen.length > 0, "must be a non-empty string when present");
    }
    if ("sourceRevision" in unit) {
      err.check(`${p}.sourceRevision`, typeof unit.sourceRevision === "string" && unit.sourceRevision.length > 0, "must be a non-empty revision string when present");
    }
  }
}

function validateEvidenceList(err, list, p, kinds) {
  err.check(p, Array.isArray(list) && list.length >= 1, "must be a non-empty array of evidence refs");
  if (!Array.isArray(list)) return;
  for (const [i, ev] of list.entries()) {
    const ep = `${p}[${i}]`;
    if (!isObject(ev)) {
      err.at(ep, `must be an object with kind (${kinds.join("|")}) and ref`);
      continue;
    }
    rejectUnknown(err, ev, ep, ["kind", "ref"]);
    err.check(ep, kinds.includes(ev.kind) && typeof ev.ref === "string" && ev.ref.length > 0, `each item needs kind (${kinds.join("|")}) and ref`);
  }
}

function validateFinding(doc, err, root) {
  rejectUnknown(err, doc, root, ["schema", "fingerprint", "runId", "caseId", "title", "coverageUnits", "disposition", "verifiedBy", "confirmed", "needs_validation", "rejected"]);
  requireFields(err, doc, root, ["schema", "fingerprint", "runId", "caseId", "title", "disposition"]);
  err.check(`${root}.schema`, doc.schema === "xpi/finding-record@1", 'must be "xpi/finding-record@1"');
  err.check(`${root}.fingerprint`, HEX16.test(String(doc.fingerprint ?? "")), "must be 16 lowercase hex chars");
  err.check(`${root}.runId`, RUN_ID.test(String(doc.runId ?? "")), "must match ^[a-z0-9][a-z0-9-]{5,63}$");
  err.check(`${root}.caseId`, typeof doc.caseId === "string" && doc.caseId.length > 0, "must be a non-empty string");
  err.check(`${root}.title`, typeof doc.title === "string" && doc.title.length > 0, "must be a non-empty string");
  if (doc.coverageUnits !== undefined) {
    err.check(`${root}.coverageUnits`, Array.isArray(doc.coverageUnits) && doc.coverageUnits.length >= 1, "must be a non-empty array of ledger unit ids");
    if (Array.isArray(doc.coverageUnits)) {
      for (const [i, unit] of doc.coverageUnits.entries()) {
        err.check(`${root}.coverageUnits[${i}]`, typeof unit === "string" && unit.length > 0, "must be a non-empty ledger unit id");
      }
    }
  }
  err.check(`${root}.disposition`, ["confirmed", "needs_validation", "rejected"].includes(doc.disposition), "invalid disposition enum");

  // Disposition payloads are mutually exclusive — a record carries exactly
  // the payload matching its disposition.
  const present = ["confirmed", "needs_validation", "rejected"].filter((k) => k in doc);
  if (present.length > 1) {
    err.at(`${root}.${present[1]}`, `disposition payloads are mutually exclusive (found ${present.join(" + ")})`);
  }

  const d = doc.disposition;
  if (d === "confirmed") {
    const c = doc.confirmed;
    if (err.check(`${root}.confirmed`, isObject(c), "confirmed requires a confirmed payload")) {
      rejectUnknown(err, c, `${root}.confirmed`, ["sourceTrace", "attackerModel", "observedResult", "affectedResource", "conditions", "evidence", "severity", "smallestFix", "verification"]);
      requireFields(err, c, `${root}.confirmed`, ["sourceTrace", "attackerModel", "observedResult", "affectedResource", "conditions", "evidence", "severity", "smallestFix", "verification"]);
      err.check(`${root}.confirmed.sourceTrace`, Array.isArray(c.sourceTrace), "must be an array of {path, lines} objects");
      if (Array.isArray(c.sourceTrace)) {
        err.check(`${root}.confirmed.sourceTrace`, c.sourceTrace.length >= 1, "needs at least one source location");
        for (const [i, tr] of c.sourceTrace.entries()) {
          err.check(`${root}.confirmed.sourceTrace[${i}]`, isObject(tr) && typeof tr.path === "string" && tr.path.length > 0 && !tr.path.includes("..") && /^\d+(-\d+)?$/.test(String(tr.lines ?? "")), "each trace needs a repo-relative path and lines like '120' or '120-145'");
          if (isObject(tr) && "note" in tr) {
            err.check(`${root}.confirmed.sourceTrace[${i}].note`, typeof tr.note === "string", "must be a string");
          }
        }
      }
      for (const field of ["attackerModel", "observedResult", "affectedResource", "smallestFix"]) {
        err.check(`${root}.confirmed.${field}`, typeof c[field] === "string" && c[field].length > 0, "must be a non-empty string");
      }
      err.check(`${root}.confirmed.conditions`, Array.isArray(c.conditions) && c.conditions.length >= 1, "must list at least one precondition");
      if (Array.isArray(c.conditions)) {
        for (const [i, cond] of c.conditions.entries()) {
          err.check(`${root}.confirmed.conditions[${i}]`, typeof cond === "string" && cond.length > 0, "each precondition must be a non-empty string");
        }
      }
      validateEvidenceList(err, c.evidence, `${root}.confirmed.evidence`, ["evidence_item", "artifact", "poc_run"]);
      err.check(`${root}.confirmed.severity`, ["info", "low", "medium", "high", "critical"].includes(c.severity), "invalid severity enum");
      if (err.check(`${root}.confirmed.verification`, isObject(c.verification), "must be an object")) {
        rejectUnknown(err, c.verification, `${root}.confirmed.verification`, ["mode", "harnessNote"]);
        err.check(`${root}.confirmed.verification.mode`, ["inter_host", "intra_target", "oob", "static_only"].includes(c.verification.mode), "invalid verification mode");
        if ("harnessNote" in c.verification) {
          err.check(`${root}.confirmed.verification.harnessNote`, typeof c.verification.harnessNote === "string", "must be a string");
        }
      }
    }
    const v = doc.verifiedBy;
    if (err.check(`${root}.verifiedBy`, isObject(v), "confirmed requires verification provenance")) {
      rejectUnknown(err, v, `${root}.verifiedBy`, ["verifierRole", "recordCheckRole", "coordinatorConfirmRole"]);
      requireFields(err, v, `${root}.verifiedBy`, ["verifierRole", "recordCheckRole"]);
      err.check(`${root}.verifiedBy.verifierRole`, typeof v.verifierRole === "string" && v.verifierRole.length > 0, "must name the fresh verifier role");
      err.check(`${root}.verifiedBy.recordCheckRole`, typeof v.recordCheckRole === "string" && v.recordCheckRole.length > 0, "must name the final record-check role");
      if ("coordinatorConfirmRole" in v) {
        err.check(`${root}.verifiedBy.coordinatorConfirmRole`, typeof v.coordinatorConfirmRole === "string" && v.coordinatorConfirmRole.length > 0, "must be a non-empty string");
      }
      if (v.verifierRole && v.recordCheckRole && v.verifierRole === v.recordCheckRole) {
        err.at(`${root}.verifiedBy.recordCheckRole`, "record check must be a different pass from the candidate verifier");
      }
    }
  } else if (d === "needs_validation") {
    const n = doc.needs_validation;
    if (err.check(`${root}.needs_validation`, isObject(n), "needs_validation requires a needs_validation payload")) {
      rejectUnknown(err, n, `${root}.needs_validation`, ["exactClaim", "unresolvedFact", "resolutionPlan"]);
      requireFields(err, n, `${root}.needs_validation`, ["exactClaim", "unresolvedFact", "resolutionPlan"]);
      for (const field of ["exactClaim", "unresolvedFact"]) {
        err.check(`${root}.needs_validation.${field}`, typeof n[field] === "string" && n[field].length > 0, "must be a non-empty string");
      }
      const plan = n.resolutionPlan;
      if (err.check(`${root}.needs_validation.resolutionPlan`, isObject(plan), "must be an object")) {
        err.check(`${root}.needs_validation.resolutionPlan.approach`, ["safe_local", "owner_observed"].includes(plan.approach), "approach must be safe_local or owner_observed");
        rejectUnknown(err, plan, `${root}.needs_validation.resolutionPlan`, ["approach", "steps"]);
        if ("steps" in plan) {
          err.check(`${root}.needs_validation.resolutionPlan.steps`, Array.isArray(plan.steps) && plan.steps.every((s) => typeof s === "string" && s.length > 0), "must be an array of non-empty step strings");
        }
      }
      err.check(`${root}.confirmed`, !("confirmed" in doc), "needs_validation carries no confirmed payload");
    }
  } else if (d === "rejected") {
    const r = doc.rejected;
    if (err.check(`${root}.rejected`, isObject(r), "rejected requires a rejected payload")) {
      rejectUnknown(err, r, `${root}.rejected`, ["disprovedClaim", "reason", "changedEvidenceWouldReopen", "evidence"]);
      requireFields(err, r, `${root}.rejected`, ["disprovedClaim", "reason", "evidence"]);
      for (const field of ["disprovedClaim", "reason"]) {
        err.check(`${root}.rejected.${field}`, typeof r[field] === "string" && r[field].length > 0, "must be a non-empty string");
      }
      if ("changedEvidenceWouldReopen" in r) {
        err.check(`${root}.rejected.changedEvidenceWouldReopen`, typeof r.changedEvidenceWouldReopen === "boolean", "must be a boolean");
      }
      validateEvidenceList(err, r.evidence, `${root}.rejected.evidence`, ["evidence_item", "artifact", "source_reading"]);
    }
  }
}

function validateDocument(doc) {
  const err = new Errors();
  if (!isObject(doc)) {
    err.at("$", "document must be a JSON object");
    return err;
  }
  switch (doc.schema) {
    case "xpi/audit-run@1":
      validateManifest(doc, err, "$");
      break;
    case "xpi/coverage-ledger@1":
      validateLedger(doc, err, "$");
      break;
    case "xpi/finding-record@1":
      validateFinding(doc, err, "$");
      break;
    default:
      err.at("$.schema", 'unknown record type — expected "xpi/audit-run@1", "xpi/coverage-ledger@1", or "xpi/finding-record@1"');
  }
  return err;
}

function validateFile(path, typeOverride) {
  let raw;
  try {
    raw = readFileSync(path, "utf8");
  } catch (e) {
    return { code: 2, messages: [`cannot read ${path}: ${e.message}`] };
  }
  let doc;
  try {
    doc = JSON.parse(raw);
  } catch (e) {
    return { code: 1, messages: [`${path}: invalid JSON: ${e.message}`] };
  }
  // A JSON null (or scalar) document is an invalid record, not a crash:
  // guard before any property access, with or without --type.
  if (!isObject(doc)) {
    return { code: 1, messages: [`${path}: document must be a JSON object`] };
  }
  if (typeOverride) {
    const expected = EXPECTED_TYPE[typeOverride];
    if (doc.schema !== expected) {
      return { code: 1, messages: [`${path}: expected ${expected}, got ${String(doc.schema)}`] };
    }
  }
  const err = validateDocument(doc);
  return { code: err.ok ? 0 : 1, messages: err.list.map((m) => `${path}: ${m}`), type: doc.schema };
}

function main(argv) {
  const args = argv.slice(2);
  const allIdx = args.indexOf("--all");
  const typeIdx = args.indexOf("--type");
  let typeOverride;
  if (typeIdx !== -1) {
    typeOverride = args[typeIdx + 1];
    if (!["manifest", "ledger", "finding"].includes(String(typeOverride))) {
      console.error("--type must be manifest, ledger, or finding");
      return 2;
    }
  }
  const skip = new Set([allIdx]);
  if (typeIdx !== -1) {
    skip.add(typeIdx);
    skip.add(typeIdx + 1);
  }
  const positional = args.filter((_, i) => !skip.has(i));

  if (allIdx !== -1) {
    const dir = positional[0];
    if (!dir) {
      console.error("usage: node scripts/validate-records.js --all <dir>");
      return 2;
    }
    let entries;
    try {
      entries = readdirSync(dir).filter((f) => f.endsWith(".json"));
    } catch (e) {
      console.error(`cannot read dir ${dir}: ${e.message}`);
      return 2;
    }
    let code = 0;
    const docs = [];
    for (const entry of entries) {
      const path = join(dir, entry);
      let doc;
      try {
        doc = JSON.parse(readFileSync(path, "utf8"));
      } catch (e) {
        console.error(`${path}: invalid JSON: ${e.message}`);
        code = 1;
        continue;
      }
      if (!isObject(doc)) {
        console.error(`${path}: document must be a JSON object`);
        code = 1;
        continue;
      }
      if (typeOverride && doc.schema !== EXPECTED_TYPE[typeOverride]) {
        console.error(`${path}: expected ${EXPECTED_TYPE[typeOverride]}, got ${String(doc.schema)}`);
        code = 1;
        continue;
      }
      const err = validateDocument(doc);
      for (const m of err.list) console.error(`${path}: ${m}`);
      if (!err.ok) {
        code = 1;
        continue;
      }
      docs.push({ path, doc });
      console.log(`OK: ${path}`);
    }
    // Cross-file linkage: a finding's coverageUnits must exist in a coverage
    // ledger sharing its runId within this batch. No ledger for the runId →
    // linkage stays unchecked (documented limitation), never accepted.
    const ledgers = new Map();
    for (const { path, doc } of docs) {
      if (doc.schema === "xpi/coverage-ledger@1" && Array.isArray(doc.units)) {
        const ids = new Set(
          doc.units.filter(isObject).map((u) => u.id).filter((id) => typeof id === "string"),
        );
        ledgers.set(doc.runId, { ids, path });
      }
    }
    for (const { path, doc } of docs) {
      if (doc.schema !== "xpi/finding-record@1" || !Array.isArray(doc.coverageUnits)) continue;
      const ledger = ledgers.get(doc.runId);
      if (!ledger) {
        // Explicit diagnostic: linkage is neither verified nor failed here.
        console.error(
          `${path}: $.coverageUnits: linkage UNCHECKED — no coverage ledger with runId ${doc.runId} in this batch`,
        );
        continue;
      }
      for (const unit of doc.coverageUnits) {
        if (!ledger.ids.has(unit)) {
          console.error(`${path}: $.coverageUnits: "${unit}" not present in ${ledger.path} (runId ${doc.runId})`);
          code = 1;
        }
      }
    }
    return code;
  }

  const file = positional[0];
  if (!file) {
    console.error("usage: node scripts/validate-records.js <file.json> [--type manifest|ledger|finding] | --all <dir>");
    return 2;
  }
  const result = validateFile(file, typeOverride);
  for (const m of result.messages) console.error(m);
  if (result.code === 0) console.log(`OK: ${result.type ?? "record"} ${file}`);
  return result.code;
}


const invokedDirectly =
  process.argv[1] && import.meta.url === `file://${realpathSync(process.argv[1])}`;
if (invokedDirectly) {
  process.exit(main(process.argv));
}

export { validateDocument, validateManifest, validateLedger, validateFinding };
