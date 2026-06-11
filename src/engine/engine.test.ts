// Smoke tests for the detection engine. Run with `npm test`.
//
// These exercise the orchestrator end-to-end with a realistic config rather
// than each detector in isolation — the merging behavior is the part most
// likely to regress.

import { test } from "node:test";
import { strict as assert } from "node:assert";
import { detect, buildEngineConfig } from "./index.js";
import { parseEnvKeys, globToHostRegex } from "./tuned.js";
import { mergeSpans } from "./spans.js";

function baseConfig(overrides: Partial<Parameters<typeof buildEngineConfig>[0]> = {}) {
  return buildEngineConfig(
    {
      detection: { gitleaks: true, fastPiiRegex: true, presidio: false },
      tune: { envKeysFrom: [], internalDomains: [], customPatterns: [] },
      allow: [],
      ...overrides,
    },
    "/tmp/nonexistent-repo",
  );
}

test("detects AWS access key id", () => {
  const text = "aws_key = AKIAIOSFODNN7EXAMPL2";
  const spans = detect(text, baseConfig());
  assert.equal(spans.length, 1);
  assert.equal(spans[0]!.class, "secrets");
  assert.equal(text.slice(spans[0]!.start, spans[0]!.end), "AKIAIOSFODNN7EXAMPL2");
});

test("respects allowlist", () => {
  const text = "aws_key = AKIAIOSFODNN7EXAMPLE";
  const spans = detect(text, baseConfig({ allow: ["AKIAIOSFODNN7EXAMPLE"] }));
  assert.equal(spans.length, 0);
});

test("detects GitHub PAT and Stripe key in same buffer", () => {
  const text = "GH=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa STRIPE=sk_live_aaaaaaaaaaaaaaaaaaaaaaaa";
  const spans = detect(text, baseConfig());
  const found = spans.map((s) => text.slice(s.start, s.end)).sort();
  assert.equal(found.length, 2);
  assert.ok(found.some((v) => v.startsWith("ghp_")));
  assert.ok(found.some((v) => v.startsWith("sk_live_")));
});

test("private key blocks span multiple lines", () => {
  const text =
    "before\n-----BEGIN RSA PRIVATE KEY-----\nABCDEFG\nHIJKLMN\n-----END RSA PRIVATE KEY-----\nafter";
  const spans = detect(text, baseConfig());
  const blocks = spans.filter((s) => s.ruleId === "private-key-block");
  assert.equal(blocks.length, 1);
  const captured = text.slice(blocks[0]!.start, blocks[0]!.end);
  assert.ok(captured.startsWith("-----BEGIN"));
  assert.ok(captured.endsWith("-----"));
});

test("generic credential assignment requires entropy", () => {
  // Placeholder — low entropy, should NOT trigger.
  const placeholder = "password = changeme";
  assert.equal(detect(placeholder, baseConfig()).length, 0);
  // High-entropy random-ish value — should trigger.
  const real = "password = X9kQ2vWp1aZmL7Tu4N3bR8";
  const spans = detect(real, baseConfig());
  assert.ok(spans.length >= 1, "expected at least one detection for high-entropy password");
});

test("URL with basic auth captures only the password", () => {
  const text = "DATABASE_URL=postgres://app:hunter2-supersecret@db.internal:5432/prod";
  const spans = detect(text, baseConfig());
  const pwdSpan = spans.find((s) => s.ruleId === "url-basic-auth");
  assert.ok(pwdSpan, "expected url-basic-auth detection");
  assert.equal(text.slice(pwdSpan!.start, pwdSpan!.end), "hunter2-supersecret");
});

test("fast PII tier finds email and Luhn-valid card, skips invalid card", () => {
  const text = "alice@example.com paid with 4111 1111 1111 1111 (good) and 1234 5678 9012 3456 (bad)";
  const spans = detect(text, baseConfig());
  const values = spans.map((s) => text.slice(s.start, s.end));
  assert.ok(values.includes("alice@example.com"));
  assert.ok(values.includes("4111 1111 1111 1111"));
  assert.ok(!values.includes("1234 5678 9012 3456"));
});

test("SSN regex rejects invalid area numbers", () => {
  const good = "SSN: 123-45-6789";
  const bad = "ID: 000-00-0000";
  assert.equal(detect(good, baseConfig()).filter((s) => s.ruleId === "pii-ssn").length, 1);
  assert.equal(detect(bad, baseConfig()).filter((s) => s.ruleId === "pii-ssn").length, 0);
});

test("repo-tuned env keys tokenize values assigned to known keys", () => {
  const cfg = buildEngineConfig(
    {
      detection: { gitleaks: false, fastPiiRegex: false, presidio: false },
      tune: { envKeysFrom: [], internalDomains: [], customPatterns: [] },
      allow: [],
    },
    "/tmp/nonexistent-repo",
  );
  cfg.tuned.envKeys = new Set(["MY_APP_TOKEN", "DB_PASSWORD"]);
  const text = "MY_APP_TOKEN=abc123xyz\nDB_PASSWORD=qwertyuiop\nUNRELATED=ok";
  const spans = detect(text, cfg);
  const values = spans.map((s) => text.slice(s.start, s.end));
  assert.deepEqual(values.sort(), ["abc123xyz", "qwertyuiop"]);
});

test("internal domain glob matches host but not adjacent text", () => {
  const re = globToHostRegex("*.internal");
  const text = "ping db.internal && curl other.example.com";
  const matches = text.match(re);
  assert.deepEqual(matches, ["db.internal"]);
});

test("env key parser handles export and comments", () => {
  const content = "# header\nexport FOO=bar\nBAZ = qux\n# QUX=ignored\nQUX=ok";
  const keys = parseEnvKeys(content);
  assert.deepEqual(Array.from(keys).sort(), ["BAZ", "FOO", "QUX"]);
});

test("spans merge keeps earlier, longer-on-tie", () => {
  const merged = mergeSpans([
    { start: 5, end: 10, class: "secrets", ruleId: "a" },
    { start: 0, end: 4, class: "secrets", ruleId: "b" },
    { start: 0, end: 6, class: "secrets", ruleId: "c" }, // overlaps; longer at same start wins over b
  ]);
  // Sorted by start; at start=0 the length-6 span wins; the length-4 dropped; then start=5 is dropped (overlaps 0..6).
  assert.deepEqual(
    merged.map((s) => [s.start, s.end, s.ruleId]),
    [[0, 6, "c"]],
  );
});
