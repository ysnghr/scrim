#!/usr/bin/env node
//
// Validate every secret rule before ship: requires `npm run build` to have
// produced bin/. Catches the failure modes unit tests don't exercise — a
// regex that compiles but has zero capture groups (so detectSecrets can't
// locate the value), a duplicate id (so audit entries collide), or a
// catastrophic-backtracking alternation (so a real scan times out).
//
// Used by CI; safe to run locally with `npm run check:rules`.

import { SECRET_RULES } from "../bin/engine/rules/secrets-rules.js";
import { IMPORTED_SECRET_RULES } from "../bin/engine/rules/gitleaks-imported-rules.js";

const all = [...SECRET_RULES, ...IMPORTED_SECRET_RULES];
const errors = [];
const ids = new Map();

for (const rule of all) {
  const where = `[${rule.id}]`;

  if (!rule.id || typeof rule.id !== "string") {
    errors.push(`${where} missing or non-string id`);
    continue;
  }
  if (ids.has(rule.id)) {
    errors.push(`${where} duplicate id (also defined at index ${ids.get(rule.id)})`);
  } else {
    ids.set(rule.id, all.indexOf(rule));
  }

  if (!(rule.pattern instanceof RegExp)) {
    errors.push(`${where} pattern is not a RegExp`);
    continue;
  }
  if (!rule.pattern.flags.includes("g")) {
    errors.push(`${where} pattern is missing the 'g' flag (detectSecrets relies on exec-in-a-loop)`);
  }

  // Capture group check: detectSecrets reads m[1]. A rule with no group will
  // fall back to m[0] but loses the value-vs-context distinction we need to
  // tokenize only the secret. Enforce at least one group.
  const probe = new RegExp("|" + rule.pattern.source);
  const m = probe.exec("");
  if (!m || m.length < 2) {
    errors.push(`${where} pattern has no capture group — detectSecrets needs group 1 = secret value`);
  }

  // Empty-match guard: a rule that matches the empty string would loop
  // forever in detectSecrets. We bump lastIndex on zero-width but it's still
  // a sign of a malformed pattern.
  if (rule.pattern.test("")) {
    errors.push(`${where} pattern matches the empty string`);
  }

  // ReDoS-shaped patterns (nested quantifiers on the same class) are a smell.
  // Crude check — flags '(.+)+', '(\w*)*' style. Whitelist known-safe rules.
  if (/\([^)]*[+*]\)[+*]/.test(rule.pattern.source)) {
    errors.push(`${where} pattern has nested quantifiers (potential ReDoS): ${rule.pattern.source}`);
  }
}

if (errors.length > 0) {
  console.error("rule validation failed:");
  for (const e of errors) console.error("  " + e);
  process.exit(1);
}

console.log(`OK ${all.length} rules validated (${SECRET_RULES.length} core + ${IMPORTED_SECRET_RULES.length} imported)`);
