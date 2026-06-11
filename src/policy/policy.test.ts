// Policy loader tests.

import { test } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  loadPolicy,
  loadPolicyFromString,
  defaultPolicy,
  toEngineInput,
  actionFor,
  PolicyError,
} from "./index.js";

function freshRepo(): string {
  return mkdtempSync(join(tmpdir(), "scrim-policy-"));
}

function writePolicy(root: string, yaml: string): void {
  const dir = join(root, ".scrim");
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "policy.yml"), yaml);
}

test("defaultPolicy returns a stable baseline", () => {
  const p = defaultPolicy();
  assert.equal(p.version, 1);
  assert.equal(p.failClosed, true);
  assert.equal(p.actions["secrets"], "redact");
  assert.equal(p.detection.gitleaks, true);
});

test("loadPolicy falls back to defaults when no file exists", () => {
  const root = freshRepo();
  const p = loadPolicy(root);
  assert.deepEqual(p, defaultPolicy());
});

test("loadPolicyFromString merges user overrides onto defaults", () => {
  const yaml = `
version: 1
actions:
  pii_internal: redact   # was alert in defaults
detection:
  presidio: true
fail_closed: false
allow:
  - "MY_ALLOWED_VALUE"
`;
  const p = loadPolicyFromString(yaml);
  assert.equal(p.actions["pii_internal"], "redact");
  assert.equal(p.actions["secrets"], "redact"); // unchanged from defaults
  assert.equal(p.detection.presidio, true);
  assert.equal(p.detection.gitleaks, true);    // unchanged
  assert.equal(p.failClosed, false);
  assert.deepEqual(p.allow, ["MY_ALLOWED_VALUE"]);
});

test("snake_case fields translate to camelCase", () => {
  const yaml = `
detection:
  fast_pii_regex: false
tune:
  env_keys_from: ["custom/.env.template"]
  internal_domains: ["*.internal", "*.corp.example.com"]
`;
  const p = loadPolicyFromString(yaml);
  assert.equal(p.detection.fastPiiRegex, false);
  assert.deepEqual(p.tune.envKeysFrom, ["custom/.env.template"]);
  assert.deepEqual(p.tune.internalDomains, ["*.internal", "*.corp.example.com"]);
});

test("custom_patterns validates regex syntax", () => {
  const yaml = `
tune:
  custom_patterns:
    - name: customer_id
      regex: "CUST-[0-9]{8}"
      class: pii_customer
`;
  const p = loadPolicyFromString(yaml);
  assert.equal(p.tune.customPatterns.length, 1);
  assert.equal(p.tune.customPatterns[0]!.regex, "CUST-[0-9]{8}");
});

test("invalid action value throws PolicyError with field path", () => {
  const yaml = `
actions:
  secrets: notreal
`;
  try {
    loadPolicyFromString(yaml, "<test>");
    assert.fail("expected PolicyError");
  } catch (err) {
    assert.ok(err instanceof PolicyError);
    assert.equal(err.path, "policy.actions.secrets");
    assert.match(err.message, /"redact"/);
  }
});

test("invalid regex in custom_patterns is rejected with line context", () => {
  const yaml = `
tune:
  custom_patterns:
    - name: bad
      regex: "["
      class: pii_customer
`;
  assert.throws(
    () => loadPolicyFromString(yaml, "<test>"),
    /policy\.tune\.custom_patterns\[0\]\.regex.*invalid regex/,
  );
});

test("wrong types are rejected with the field path", () => {
  assert.throws(
    () => loadPolicyFromString("fail_closed: notabool", "<test>"),
    /policy\.fail_closed.*expected boolean/,
  );
  assert.throws(
    () => loadPolicyFromString("detection: yes", "<test>"),
    /policy\.detection.*expected an object/,
  );
});

test("loadPolicy reads .scrim/policy.yml from the repo root", () => {
  const root = freshRepo();
  writePolicy(root, "actions:\n  secrets: block\n");
  const p = loadPolicy(root);
  assert.equal(p.actions["secrets"], "block");
});

test("toEngineInput maps cleanly", () => {
  const p = loadPolicyFromString(`
detection: { gitleaks: false, presidio: true, fast_pii_regex: false }
tune:
  env_keys_from: ["a"]
  internal_domains: ["b.internal"]
  custom_patterns:
    - { name: x, regex: "X+", class: secrets }
allow: ["safe1"]
`);
  const e = toEngineInput(p);
  assert.deepEqual(e.detection, { gitleaks: false, presidio: true, fastPiiRegex: false });
  assert.deepEqual(e.tune.envKeysFrom, ["a"]);
  assert.deepEqual(e.tune.internalDomains, ["b.internal"]);
  assert.equal(e.tune.customPatterns[0]!.name, "x");
  assert.deepEqual(e.allow, ["safe1"]);
});

test("actionFor defaults to redact for unknown classes", () => {
  const p = defaultPolicy();
  assert.equal(actionFor(p, "secrets"), "redact");
  assert.equal(actionFor(p, "totally_new_class"), "redact");
});

test("rejects unsupported version", () => {
  assert.throws(
    () => loadPolicyFromString("version: 2", "<test>"),
    /version.*only version 1/,
  );
});

test("empty policy file yields defaults", () => {
  assert.deepEqual(loadPolicyFromString(""), defaultPolicy());
  assert.deepEqual(loadPolicyFromString("\n# only a comment\n"), defaultPolicy());
});

test("vault block: max_entries and wipe_on_stop translate to camelCase", () => {
  const p = loadPolicyFromString(`
vault:
  max_entries: 500
  wipe_on_stop: false
`);
  assert.equal(p.vault.maxEntries, 500);
  assert.equal(p.vault.wipeOnStop, false);
});

test("vault block: defaults preserved when not specified", () => {
  const p = loadPolicyFromString("actions:\n  secrets: alert\n");
  assert.equal(p.vault.maxEntries, 10000);
  assert.equal(p.vault.wipeOnStop, true);
});

test("vault.max_entries: negative is rejected", () => {
  assert.throws(
    () => loadPolicyFromString("vault:\n  max_entries: -5\n", "<test>"),
    /policy\.vault\.max_entries.*non-negative integer/,
  );
});

test("vault.wipe_on_stop: wrong type is rejected", () => {
  assert.throws(
    () => loadPolicyFromString("vault:\n  wipe_on_stop: maybe\n", "<test>"),
    /policy\.vault\.wipe_on_stop.*expected boolean/,
  );
});
