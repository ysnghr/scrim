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

test("generic credential: placeholder denylist rejects look-like-secret-but-isnt values", () => {
  // Each value is a placeholder — should NOT be flagged.
  const cases = [
    "password = changeme123",
    "secret = your_api_key",
    "api_key = placeholder",
    "auth_token = hunter2",
    "client_secret = correct-horse-battery-staple",
    "password = test",
    "password = TODO",
    "password = password",
    "password = p@ssw0rd",
  ];
  for (const text of cases) {
    const spans = detect(text, baseConfig());
    const generic = spans.filter((s) => s.ruleId === "generic-credential-assignment");
    assert.equal(generic.length, 0, `placeholder should be rejected: ${text}`);
  }
});

test("generic credential: shape filters reject IPs, URLs, and greetings", () => {
  const cases = [
    'password = 127.0.0.1',
    'password = 10.20.30.40',
    'password = http://internal/foo',
    'secret = "Hello, World!"',
    'password = postgres://user@host/db',
  ];
  for (const text of cases) {
    const spans = detect(text, baseConfig());
    const generic = spans.filter((s) => s.ruleId === "generic-credential-assignment");
    assert.equal(generic.length, 0, `shape-filtered value should be rejected: ${text}`);
  }
});

test("generic credential: lowered threshold catches low-entropy real passwords", () => {
  // `Password1` has entropy ~2.95 — below the old 3.0 threshold but above
  // the new 2.7 default, and it does not match any placeholder/shape filter.
  const text = "password = Password1";
  const spans = detect(text, baseConfig());
  const generic = spans.filter((s) => s.ruleId === "generic-credential-assignment");
  assert.equal(generic.length, 1, "Password1 should be flagged under the new 2.7 threshold");
});

test("generic credential: policy can raise the threshold to be stricter", () => {
  // Same Password1 fixture, but raise threshold above its entropy (~2.95).
  const cfg = buildEngineConfig(
    {
      detection: {
        gitleaks: true, fastPiiRegex: false, presidio: false,
        entropy: { genericCredential: 4.0 },
      },
      tune: { envKeysFrom: [], internalDomains: [], customPatterns: [] },
      allow: [],
    },
    "/tmp/nonexistent-repo",
  );
  const spans = detect("password = Password1", cfg);
  const generic = spans.filter((s) => s.ruleId === "generic-credential-assignment");
  assert.equal(generic.length, 0, "raising threshold to 4.0 should reject Password1");
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

// --- Vendor rule coverage ---
//
// One row per added vendor rule. Each row asserts (1) the rule fires on a
// realistic-looking fixture and (2) the rule does NOT fire on a near-miss
// (wrong prefix, wrong length, or obvious placeholder). Synthetic — none of
// these are real credentials, but they match the published format so the
// regex tightness can drift if we change a quantifier carelessly.
const VENDOR_FIXTURES: ReadonlyArray<{
  ruleId: string;
  hit: string;
  miss: string;
}> = [
  {
    ruleId: "digitalocean-token",
    hit: "TOKEN=dop_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    miss: "TOKEN=dop_v2_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  },
  {
    ruleId: "hashicorp-vault-token",
    hit:
      "VAULT_TOKEN=hvs.aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcDeFgHiJkLmNoPqR",
    miss: "VAULT_TOKEN=hvs.short",
  },
  {
    ruleId: "heroku-platform-token",
    hit: "HEROKU_API_KEY=HRKU-a1b2c3d4e5f6789012345678901234567890ab",
    miss: "HEROKU_API_KEY=HRKU-tooshort",
  },
  {
    ruleId: "sendinblue-key",
    hit:
      "BREVO=xkeysib-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef-aB3cD7eF9gH2iJ4k",
    miss: "BREVO=xkeysib-nope",
  },
  {
    ruleId: "slack-webhook-url",
    hit: "url=https://hooks.slack.com/services/T01ABCDEF/B02GHIJK1/aBcDeFgHiJkLmNoPqRsTuVwX",
    miss: "url=https://example.com/services/T01ABCDEF/B02GHIJK1/aBcDeFgHiJkLmNoPqRsTuVwX",
  },
  {
    ruleId: "sentry-token",
    hit:
      "SENTRY_AUTH_TOKEN=sntrys_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcDeFgHiJkLmNoPqRsTuVwXyZ01",
    miss: "SENTRY_AUTH_TOKEN=sntry_aB3cD7eF9gH2iJ4kL6mN8oP0",
  },
  {
    ruleId: "shopify-token",
    hit: "SHOP=shpat_0123456789abcdef0123456789abcdef",
    miss: "SHOP=shpxx_0123456789abcdef0123456789abcdef",
  },
  {
    ruleId: "square-access-token",
    hit: "SQUARE=EAAAaBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcDeFgHiJkLmNoPqRsTuVwX",
    miss: "SQUARE=EAAB_tooshortforsquare",
  },
  {
    ruleId: "plaid-key",
    hit: "PLAID=access-sandbox-12345678-90ab-cdef-1234-567890abcdef",
    miss: "PLAID=access-staging-12345678-90ab-cdef-1234-567890abcdef",
  },
  {
    ruleId: "huggingface-token",
    hit: "HF=hf_AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIj",
    miss: "HF=hf_short",
  },
  {
    ruleId: "linear-api-key",
    hit: "LINEAR=lin_api_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcD",
    miss: "LINEAR=lin_api_short",
  },
  {
    ruleId: "notion-integration-token",
    hit: "NOTION=secret_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789ABCDEfg",
    miss: "NOTION=secret_short",
  },
  {
    ruleId: "asana-pat",
    hit: "ASANA=1/1234567890123456:0123456789abcdef0123456789abcdef",
    miss: "ASANA=1/short:0123456789abcdef0123456789abcdef",
  },
  {
    ruleId: "atlassian-api-token",
    hit:
      "ATLASSIAN=ATATT3xFfGF0aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456=01ABCDEF",
    miss: "ATLASSIAN=ATATT3short=01ABCDEF",
  },
  {
    ruleId: "postman-api-key",
    hit: "POSTMAN=PMAK-0123456789abcdef01234567-0123456789abcdef0123456789abcdef34",
    miss: "POSTMAN=PMAK-tooshort-tooshort",
  },
  {
    ruleId: "sonar-token",
    hit: "SONAR=squ_0123456789abcdef0123456789abcdef01234567",
    miss: "SONAR=sqx_0123456789abcdef0123456789abcdef01234567",
  },
  {
    ruleId: "new-relic-api-key",
    hit: "NEW_RELIC_LICENSE_KEY=NRAK-ABCDEFGHIJKLMNOPQRSTUVWX012",
    miss: "NEW_RELIC_LICENSE_KEY=NRAK-tooshort",
  },
  {
    ruleId: "jfrog-api-key",
    hit:
      "JFROG=AKCpabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefg",
    miss: "JFROG=AKCxabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefg",
  },
  {
    ruleId: "dropbox-token",
    hit:
      "DROPBOX=sl.aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcDeFgHiJkLmNoPqRsTuV",
    miss: "DROPBOX=sl.shortdropbox",
  },
  {
    ruleId: "pypi-token",
    hit:
      "PYPI=pypi-AgEIcHlwaS5vcmcCJEFiQ2RFZkdoSWpLbE1uT3BRclN0VXZXeFla0123456789aBcDeFgH",
    miss: "PYPI=pypi-SomethingElseEntirely-0123456789",
  },
  {
    ruleId: "rubygems-api-key",
    hit: "GEMS=rubygems_0123456789abcdef0123456789abcdef0123456789abcdef",
    miss: "GEMS=rubygems_tooshort",
  },
  {
    ruleId: "telegram-bot-token",
    hit: "TELEGRAM=987654321:aB3cD7eF9gH2iJ4kL6mN8oP0qR2sT4uV6wX",
    miss: "TELEGRAM=987654321:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // shape matches but entropy < 3.0
  },
  {
    ruleId: "discord-bot-token",
    hit: "DISCORD=MTAxMjM0NTY3ODkwMTIzNDU2.GhYzKl.0aB3cD7eF9gH2iJ4kL6mN8oP0qR",
    miss: "DISCORD=MTAxMjM0NTY3ODkwMTIzNDU2.aaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaa", // shape matches but entropy < 3.0
  },
];

for (const { ruleId, hit, miss } of VENDOR_FIXTURES) {
  test(`vendor rule fires: ${ruleId}`, () => {
    const spans = detect(hit, baseConfig());
    const matched = spans.filter((s) => s.ruleId === ruleId);
    assert.equal(matched.length, 1, `expected ${ruleId} to match exactly once in: ${hit}`);
  });

  test(`vendor rule does not fire on near-miss: ${ruleId}`, () => {
    const spans = detect(miss, baseConfig());
    const matched = spans.filter((s) => s.ruleId === ruleId);
    assert.equal(matched.length, 0, `expected ${ruleId} NOT to match in: ${miss}`);
  });
}

// --- Imported (Gitleaks-derived) rule coverage ---
//
// Builders for fixture strings of an exact length keep the table-driven tests
// honest: rule patterns frequently use exact-count quantifiers and synthetic
// fixtures off by ±1 silently stop firing.
function alpha(n: number): string {
  let out = "";
  while (out.length < n) out += "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789";
  return out.slice(0, n);
}
function hex(n: number): string {
  let out = "";
  while (out.length < n) out += "0123456789abcdef";
  return out.slice(0, n);
}
function upperHex(n: number): string {
  let out = "";
  while (out.length < n) out += "0123456789ABCDEF";
  return out.slice(0, n);
}

const IMPORTED_FIXTURES: ReadonlyArray<{
  ruleId: string;
  hit: string;
  miss: string;
}> = [
  {
    ruleId: "mailchimp-api-key",
    hit: `MC=${hex(32)}-us12`,
    miss: `MC=${hex(32)}-eu12`,
  },
  {
    ruleId: "pulumi-access-token",
    hit: `PULUMI=pul-${hex(40)}`,
    miss: `PULUMI=pul-${hex(20)}`,
  },
  {
    ruleId: "doppler-token",
    hit: `DOPPLER=dp.pt.${alpha(43)}`,
    miss: `DOPPLER=dp.too.${alpha(10)}`,
  },
  {
    ruleId: "databricks-token",
    hit: `DATABRICKS=dapi${hex(32)}`,
    miss: `DATABRICKS=dapi${hex(10)}`,
  },
  {
    ruleId: "fly-io-token",
    hit: `FLY=fo1_${alpha(45)}`,
    miss: `FLY=fo1_${alpha(10)}`,
  },
  {
    ruleId: "circleci-personal-token",
    hit: `CCI=CCIPRJ_${alpha(45)}`,
    miss: `CCI=CCI_${alpha(45)}`,
  },
  {
    ruleId: "shippo-token",
    hit: `SHIPPO=shippo_live_${hex(40)}`,
    miss: `SHIPPO=shippo_dev_${hex(40)}`,
  },
  {
    ruleId: "terraform-cloud-token",
    hit: `TF=${alpha(14)}.atlasv1.${alpha(65)}`,
    miss: `TF=${alpha(14)}.atlasv2.${alpha(65)}`,
  },
  {
    ruleId: "yandex-iam-token",
    hit: `YC=t1.${alpha(25)}.${alpha(43)}`,
    miss: `YC=t1.${alpha(25)}.${alpha(10)}`,
  },
  {
    ruleId: "yandex-oauth-token",
    hit: `YC=y0_${alpha(60)}`,
    miss: `YC=y0_${alpha(10)}`,
  },
  {
    ruleId: "duffel-key",
    hit: `DUFFEL=duffel_live_${alpha(42)}`,
    miss: `DUFFEL=duffel_dev_${alpha(42)}`,
  },
  {
    ruleId: "nuget-api-key",
    hit: `NUGET=oy2${hex(43)}`,
    miss: `NUGET=oy3${hex(43)}`,
  },
  {
    ruleId: "clickup-token",
    hit: `CLICKUP=pk_1234567_${upperHex(32)}`,
    miss: `CLICKUP=pk_1234567_${hex(32)}`, // requires uppercase hex
  },
  {
    ruleId: "grafana-service-account-token",
    hit: `GRAFANA=glsa_${alpha(32)}_${hex(8)}`,
    miss: `GRAFANA=glsa_${alpha(32)}_${hex(4)}`,
  },
  {
    ruleId: "supabase-publishable-key",
    hit: `SUPABASE=sbp_${alpha(40)}`,
    miss: `SUPABASE=sbp_${alpha(10)}`,
  },
  {
    ruleId: "discord-webhook-url",
    hit: `DISCORD=https://discord.com/api/webhooks/123456789012345/${alpha(65)}`,
    miss: `DISCORD=https://discord.com/api/webhooks/123456789012345/${alpha(10)}`,
  },
];

for (const { ruleId, hit, miss } of IMPORTED_FIXTURES) {
  test(`imported rule fires: ${ruleId}`, () => {
    const spans = detect(hit, baseConfig());
    const matched = spans.filter((s) => s.ruleId === ruleId);
    assert.equal(matched.length, 1, `expected ${ruleId} to match exactly once in: ${hit}`);
  });

  test(`imported rule does not fire on near-miss: ${ruleId}`, () => {
    const spans = detect(miss, baseConfig());
    const matched = spans.filter((s) => s.ruleId === ruleId);
    assert.equal(matched.length, 0, `expected ${ruleId} NOT to match in: ${miss}`);
  });
}

test("custom patterns from policy detect domain-specific secrets", () => {
  // End-to-end check that tune.customPatterns flows through buildEngineConfig
  // and reaches the engine. Without this, a user adding a custom_patterns entry
  // to policy.yml could silently fail (the field validates but never fires).
  const cfg = buildEngineConfig(
    {
      detection: { gitleaks: false, fastPiiRegex: false, presidio: false },
      tune: {
        envKeysFrom: [],
        internalDomains: [],
        customPatterns: [
          { name: "internal-license", regex: "ACME-LIC-[A-Z0-9]{16}", class: "secrets" },
        ],
      },
      allow: [],
    },
    "/tmp/nonexistent-repo",
  );
  const text = "license = ACME-LIC-ABCD1234EFGH5678 and license = ACME-LIC-NOPE";
  const spans = detect(text, cfg);
  // First should match (16 alphanumeric); second is too short.
  assert.equal(spans.length, 1);
  assert.equal(spans[0]!.ruleId, "tuned-custom:internal-license");
  assert.equal(text.slice(spans[0]!.start, spans[0]!.end), "ACME-LIC-ABCD1234EFGH5678");
});
