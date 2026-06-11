// Synthesize a labeled benchmark corpus.
//
// Output layout under <out>/:
//   secrets/<scenario>.<ext>     one file per scenario
//   pii/<scenario>.<ext>
//   labels.jsonl                 one Label per line (see types.ts)
//
// The synthesizer is deterministic: same seed → same bytes → same labels. That
// lets CI compare runs across commits without the file churn that a random
// generator would cause. All "secrets" produced here are synthetic — they
// match the *shape* a real provider key takes but the random bytes were never
// issued by anyone. Public-test fixtures (e.g. AWS docs example key, Stripe
// test mode card) are pulled in deliberately as lookalikes.
import { mkdirSync, writeFileSync, rmSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
// Mulberry32: small, deterministic, good enough for corpus synthesis.
function mulberry32(seed) {
    let t = seed >>> 0;
    return () => {
        t = (t + 0x6d2b79f5) >>> 0;
        let r = Math.imul(t ^ (t >>> 15), 1 | t);
        r = (r + Math.imul(r ^ (r >>> 7), 61 | r)) ^ r;
        return ((r ^ (r >>> 14)) >>> 0) / 4294967296;
    };
}
const ALPHA = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const HEX = "0123456789abcdef";
const UPPER_ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
function pick(rng, chars, n) {
    let s = "";
    for (let i = 0; i < n; i++)
        s += chars[Math.floor(rng() * chars.length)];
    return s;
}
// Provider-shaped synthetic secrets. The leading "fixed" prefix is what makes
// each pattern detectable; the random tail is high-entropy so any
// reasonable detector should fire.
function synthSecret(kind, rng) {
    switch (kind) {
        case "aws-access-key-id": return "AKIA" + pick(rng, UPPER_ALNUM, 16);
        case "aws-secret-key": return pick(rng, ALPHA + "/+", 40);
        case "google-api-key": return "AIza" + pick(rng, ALPHA + "-_", 35);
        case "github-token": return "ghp_" + pick(rng, ALPHA, 36);
        case "gitlab-token": return "glpat-" + pick(rng, ALPHA + "-_", 20);
        case "stripe-live-secret": return "sk_live_" + pick(rng, ALPHA, 28);
        case "slack-bot": return "xoxb-" + pick(rng, ALPHA, 10) + "-" + pick(rng, ALPHA, 12);
        case "anthropic-key": return "sk-ant-" + pick(rng, ALPHA + "-_", 40);
        case "openai-key": return "sk-" + pick(rng, ALPHA, 48);
        case "npm-token": return "npm_" + pick(rng, ALPHA, 36);
        case "twilio-key": return "SK" + pick(rng, HEX, 32);
        case "sendgrid-key": return "SG." + pick(rng, ALPHA + "-_", 22) + "." + pick(rng, ALPHA + "-_", 43);
        case "do-token": return "dop_v1_" + pick(rng, HEX, 64);
        case "jwt": {
            const seg = (n) => pick(rng, ALPHA + "-_", n);
            return `${seg(36)}.${seg(120)}.${seg(43)}`;
        }
        case "db-password": return pick(rng, ALPHA + "!@#$%", 24);
        case "private-key": {
            // A multi-line PEM block. Detection is by header/footer, not content,
            // so the inside can be arbitrary.
            const body = [];
            for (let i = 0; i < 24; i++)
                body.push(pick(rng, ALPHA + "+/", 64));
            return `-----BEGIN RSA PRIVATE KEY-----\n${body.join("\n")}\n-----END RSA PRIVATE KEY-----`;
        }
        default: throw new Error(`unknown secret kind: ${kind}`);
    }
}
// Public test fixtures that look like secrets but are documented placeholders.
// Detecting these IS a false positive — they're either in vendor docs, test
// mode, or famously inert.
const PUBLIC_LOOKALIKES = {
    "aws-docs-example": "AKIAIOSFODNN7EXAMPLE",
    "stripe-test-card": "4111111111111111",
    "stripe-test-secret": "sk_test_4eC39HqLyjWDarjtT1zdp7dc",
    "github-example": "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "jwt-example": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    "placeholder-1": "changeme",
    "placeholder-2": "xxxxxxxxxxxxxxxxxxxxxxxx",
    "placeholder-3": "your-secret-here",
};
// Luhn-valid synthetic card numbers, plus a fake but Luhn-passing SSN-shape.
const PII_SAMPLES = {
    email_real: () => `alice.${randSuffix()}@example-customer.com`,
    email_intern: () => `eng-${randSuffix()}@internal.acme.local`,
    ssn_real: "412-23-9876",
    ssn_placeholder: "000-00-0000",
    phone_real: "+1 (415) 555-0142",
    phone_lookalike: "1-800-555-0100", // documented "555-01xx" reserved range
    card_real: "4539578763621486", // synthetic, passes Luhn
    card_test: "4242424242424242", // Stripe test card
    card_invalid: "1234567812345670", // fails Luhn — should NOT match
};
let suffixCounter = 0;
function randSuffix() {
    suffixCounter++;
    return suffixCounter.toString(36).padStart(4, "0");
}
// Build a file from a template that contains §INS{i}§ markers. Returns the
// finished bytes plus a Label for each replaced marker (positions are bytes
// in the finished output).
function materialize(relPath, template, insertions) {
    let out = "";
    let cursor = 0;
    const labels = [];
    for (let i = 0; i < insertions.length; i++) {
        const ins = insertions[i];
        const idx = template.indexOf(ins.marker, cursor);
        if (idx < 0)
            throw new Error(`marker ${ins.marker} not found in template for ${relPath}`);
        out += template.slice(cursor, idx);
        const start = out.length;
        out += ins.value;
        const end = out.length;
        if (ins.variant === "real") {
            labels.push({
                file: relPath, start, end,
                class: ins.klass, ruleId: ins.ruleId,
                variant: "real", value: ins.value,
            });
        }
        else {
            // Record lookalike/placeholder so the scorer can recognise it if a
            // runner flags it. Bounds carry the value for debugging.
            labels.push({
                file: relPath, start, end,
                class: ins.klass, ruleId: ins.ruleId,
                variant: ins.variant, value: ins.value,
            });
        }
        cursor = idx + ins.marker.length;
    }
    out += template.slice(cursor);
    return { bytes: out, labels };
}
const SCENARIOS = [
    // ---- secrets corpus ----
    (rng) => {
        const aws = synthSecret("aws-access-key-id", rng);
        const awsSecret = synthSecret("aws-secret-key", rng);
        return {
            relPath: "secrets/dotenv-aws.env",
            template: `# production credentials, do not commit
AWS_ACCESS_KEY_ID=§INS0§
AWS_SECRET_ACCESS_KEY=§INS1§
AWS_REGION=us-east-1
LOG_LEVEL=info
`,
            insertions: [
                { marker: "§INS0§", kind: "aws-access-key-id", variant: "real", klass: "secrets", ruleId: "aws-access-key-id", value: aws },
                { marker: "§INS1§", kind: "aws-secret-key", variant: "real", klass: "secrets", ruleId: "aws-secret-key", value: awsSecret },
            ],
        };
    },
    (rng) => {
        const v = synthSecret("github-token", rng);
        const v2 = synthSecret("npm-token", rng);
        return {
            relPath: "secrets/dotenv-ci.env",
            template: `GITHUB_TOKEN=§INS0§
NPM_TOKEN=§INS1§
CI_CACHE_DIR=/tmp/ci-cache
NODE_ENV=production
`,
            insertions: [
                { marker: "§INS0§", kind: "github-token", variant: "real", klass: "secrets", ruleId: "github-token-classic", value: v },
                { marker: "§INS1§", kind: "npm-token", variant: "real", klass: "secrets", ruleId: "npm-token", value: v2 },
            ],
        };
    },
    (rng) => {
        const stripeLive = synthSecret("stripe-live-secret", rng);
        return {
            relPath: "secrets/appsettings.json",
            template: `{
  "ConnectionStrings": {
    "Default": "Server=db.prod.internal;Database=app;User Id=app;Password=§INS0§;"
  },
  "Stripe": {
    "SecretKey": "§INS1§",
    "PublishableKey": "pk_live_abcd1234"
  },
  "Stripe_TestMode": {
    "TestKey": "§INS2§"
  }
}
`,
            insertions: [
                { marker: "§INS0§", kind: "db-password", variant: "real", klass: "secrets", ruleId: "db-password-quoted", value: synthSecret("db-password", rng) },
                { marker: "§INS1§", kind: "stripe-live-secret", variant: "real", klass: "secrets", ruleId: "stripe-key", value: stripeLive },
                { marker: "§INS2§", kind: "stripe-test", variant: "lookalike", klass: "secrets", ruleId: "stripe-key", value: PUBLIC_LOOKALIKES["stripe-test-secret"] },
            ],
        };
    },
    (rng) => {
        return {
            relPath: "secrets/terraform.tfvars",
            template: `environment      = "production"
aws_access_key   = "§INS0§"
aws_secret_key   = "§INS1§"
google_api_key   = "§INS2§"
# example from docs, do NOT change:
example_aws_key  = "§INS3§"
region           = "eu-west-1"
`,
            insertions: [
                { marker: "§INS0§", kind: "aws-access-key-id", variant: "real", klass: "secrets", ruleId: "aws-access-key-id", value: synthSecret("aws-access-key-id", rng) },
                { marker: "§INS1§", kind: "aws-secret-key", variant: "real", klass: "secrets", ruleId: "aws-secret-key", value: synthSecret("aws-secret-key", rng) },
                { marker: "§INS2§", kind: "google-api-key", variant: "real", klass: "secrets", ruleId: "google-api-key", value: synthSecret("google-api-key", rng) },
                { marker: "§INS3§", kind: "aws-docs-example", variant: "lookalike", klass: "secrets", ruleId: "aws-access-key-id", value: PUBLIC_LOOKALIKES["aws-docs-example"] },
            ],
        };
    },
    (rng) => {
        return {
            relPath: "secrets/k8s-secret.yaml",
            template: `apiVersion: v1
kind: Secret
metadata:
  name: app-credentials
type: Opaque
stringData:
  ANTHROPIC_API_KEY: §INS0§
  OPENAI_API_KEY: §INS1§
  SLACK_BOT_TOKEN: §INS2§
  SENDGRID_KEY: §INS3§
`,
            insertions: [
                { marker: "§INS0§", kind: "anthropic-key", variant: "real", klass: "secrets", ruleId: "anthropic-api-key", value: synthSecret("anthropic-key", rng) },
                { marker: "§INS1§", kind: "openai-key", variant: "real", klass: "secrets", ruleId: "openai-api-key", value: synthSecret("openai-key", rng) },
                { marker: "§INS2§", kind: "slack-bot", variant: "real", klass: "secrets", ruleId: "slack-token", value: synthSecret("slack-bot", rng) },
                { marker: "§INS3§", kind: "sendgrid-key", variant: "real", klass: "secrets", ruleId: "sendgrid-key", value: synthSecret("sendgrid-key", rng) },
            ],
        };
    },
    (rng) => {
        return {
            relPath: "secrets/connection-strings.config",
            template: `# Various forms of database URLs with embedded credentials
PG_URL=postgres://app_user:§INS0§@db-1.prod.internal:5432/app
MONGO_URL=mongodb+srv://reader:§INS1§@cluster0.mongo.example.com/data
REDIS_URL=redis://:§INS2§@cache.internal:6379
HEALTHCHECK_URL=https://monitor:hunter2@status.example.com/ping
`,
            insertions: [
                { marker: "§INS0§", kind: "db-password", variant: "real", klass: "secrets", ruleId: "url-basic-auth", value: synthSecret("db-password", rng) },
                { marker: "§INS1§", kind: "db-password", variant: "real", klass: "secrets", ruleId: "url-basic-auth", value: synthSecret("db-password", rng) },
                { marker: "§INS2§", kind: "db-password", variant: "real", klass: "secrets", ruleId: "url-basic-auth", value: synthSecret("db-password", rng) },
            ],
        };
    },
    (rng) => {
        const pem = synthSecret("private-key", rng);
        return {
            relPath: "secrets/deploy-key.pem",
            template: `§INS0§\n`,
            insertions: [
                { marker: "§INS0§", kind: "private-key", variant: "real", klass: "secrets", ruleId: "private-key-block", value: pem },
            ],
        };
    },
    (rng) => {
        return {
            relPath: "secrets/placeholders.env",
            template: `# Should all be IGNORED — they are placeholders, not real secrets.
API_TOKEN=§INS0§
SECRET=§INS1§
DB_PASSWORD=§INS2§
JWT=§INS3§
`,
            insertions: [
                { marker: "§INS0§", kind: "placeholder-1", variant: "placeholder", klass: "secrets", ruleId: "any", value: "changeme" },
                { marker: "§INS1§", kind: "placeholder-3", variant: "placeholder", klass: "secrets", ruleId: "any", value: "your-secret-here" },
                { marker: "§INS2§", kind: "placeholder-2", variant: "placeholder", klass: "secrets", ruleId: "any", value: "xxxxxxxxxxxxxxxxxxxxxxxx" },
                { marker: "§INS3§", kind: "jwt-example", variant: "lookalike", klass: "secrets", ruleId: "jwt", value: PUBLIC_LOOKALIKES["jwt-example"] },
            ],
        };
    },
    (rng) => {
        return {
            relPath: "secrets/jwt-and-do.config.toml",
            template: `[auth]
session_jwt = "§INS0§"

[hosting]
do_token = "§INS1§"

[twilio]
account_sid = "§INS2§"
`,
            insertions: [
                { marker: "§INS0§", kind: "jwt", variant: "real", klass: "secrets", ruleId: "jwt", value: synthSecret("jwt", rng) },
                { marker: "§INS1§", kind: "do-token", variant: "real", klass: "secrets", ruleId: "digitalocean-token", value: synthSecret("do-token", rng) },
                { marker: "§INS2§", kind: "twilio-key", variant: "real", klass: "secrets", ruleId: "twilio-key", value: synthSecret("twilio-key", rng) },
            ],
        };
    },
    (rng) => {
        // Large-ish config file (~500 lines) — diluted secrets across noise. Tests
        // both detection precision and scanning throughput.
        const lines = [];
        for (let i = 0; i < 480; i++) {
            lines.push(`# config option ${i} — placeholder noise to dilute signal`);
            lines.push(`setting_${i} = ${pick(rng, ALPHA, 24)}`);
        }
        // Two secrets buried at known offsets.
        lines.splice(120, 0, `database_password = "§INS0§"`);
        lines.splice(320, 0, `github_pat = "§INS1§"`);
        return {
            relPath: "secrets/large-config.cfg",
            template: lines.join("\n") + "\n",
            insertions: [
                { marker: "§INS0§", kind: "db-password", variant: "real", klass: "secrets", ruleId: "db-password-quoted", value: synthSecret("db-password", rng) },
                { marker: "§INS1§", kind: "github-token", variant: "real", klass: "secrets", ruleId: "github-token-classic", value: synthSecret("github-token", rng) },
            ],
        };
    },
    // ---- pii corpus ----
    (rng) => {
        const email1 = PII_SAMPLES.email_real();
        const email2 = PII_SAMPLES.email_real();
        return {
            relPath: "pii/users.csv",
            template: `id,name,email,phone,ssn,notes
1,Alice Wang,§INS0§,§INS1§,§INS2§,vip
2,Bob Diaz,§INS3§,n/a,§INS4§,
3,Carol Patel,§INS5§,§INS6§,§INS7§,
`,
            insertions: [
                { marker: "§INS0§", kind: "email", variant: "real", klass: "pii_email", ruleId: "pii-email", value: email1 },
                { marker: "§INS1§", kind: "phone", variant: "real", klass: "pii_phone", ruleId: "pii-phone", value: PII_SAMPLES.phone_real },
                { marker: "§INS2§", kind: "ssn", variant: "real", klass: "pii_ssn", ruleId: "pii-ssn", value: PII_SAMPLES.ssn_real },
                { marker: "§INS3§", kind: "email", variant: "real", klass: "pii_email", ruleId: "pii-email", value: email2 },
                { marker: "§INS4§", kind: "ssn", variant: "placeholder", klass: "pii_ssn", ruleId: "pii-ssn", value: PII_SAMPLES.ssn_placeholder },
                { marker: "§INS5§", kind: "email", variant: "real", klass: "pii_email", ruleId: "pii-email", value: PII_SAMPLES.email_real() },
                { marker: "§INS6§", kind: "phone", variant: "lookalike", klass: "pii_phone", ruleId: "pii-phone", value: PII_SAMPLES.phone_lookalike },
                { marker: "§INS7§", kind: "ssn", variant: "real", klass: "pii_ssn", ruleId: "pii-ssn", value: "298-12-3456" },
            ],
        };
    },
    (rng) => {
        return {
            relPath: "pii/payments.log",
            template: `2026-06-11 10:01 charge ok user=alice card=§INS0§ amount=42.00
2026-06-11 10:02 charge ok user=bob   card=§INS1§ amount=12.00
2026-06-11 10:03 charge fail user=eve card=§INS2§ reason=insufficient
2026-06-11 10:04 ref id=§INS3§ source=test
`,
            insertions: [
                { marker: "§INS0§", kind: "card", variant: "real", klass: "pii_card", ruleId: "pii-card", value: PII_SAMPLES.card_real },
                { marker: "§INS1§", kind: "card", variant: "lookalike", klass: "pii_card", ruleId: "pii-card", value: PII_SAMPLES.card_test },
                { marker: "§INS2§", kind: "card-bad", variant: "lookalike", klass: "pii_card", ruleId: "pii-card", value: PII_SAMPLES.card_invalid },
                // A 16-digit number that ISN'T a card — order number, won't pass Luhn.
                { marker: "§INS3§", kind: "non-card", variant: "lookalike", klass: "pii_card", ruleId: "pii-card", value: "9999000088887777" },
            ],
        };
    },
    (rng) => {
        return {
            relPath: "pii/support-ticket.md",
            template: `# Ticket #4821

Customer email: §INS0§
Phone: §INS1§
Mailing address: 123 Main St, Springfield IL 62704
SSN provided for ID verification: §INS2§

Notes:
- Reached out via §INS3§
- Promised callback by 3pm
`,
            insertions: [
                { marker: "§INS0§", kind: "email", variant: "real", klass: "pii_email", ruleId: "pii-email", value: PII_SAMPLES.email_real() },
                { marker: "§INS1§", kind: "phone", variant: "real", klass: "pii_phone", ruleId: "pii-phone", value: "(312) 555-7841" },
                { marker: "§INS2§", kind: "ssn", variant: "real", klass: "pii_ssn", ruleId: "pii-ssn", value: "651-09-4422" },
                { marker: "§INS3§", kind: "email", variant: "real", klass: "pii_email", ruleId: "pii-email", value: PII_SAMPLES.email_real() },
            ],
        };
    },
];
export function generateCorpus(opts) {
    const rng = mulberry32(opts.seed ?? 0xC0DECAFE);
    suffixCounter = 0;
    if (opts.clean && existsSync(opts.outDir)) {
        rmSync(opts.outDir, { recursive: true, force: true });
    }
    mkdirSync(opts.outDir, { recursive: true });
    const allLabels = [];
    const files = [];
    let totalBytes = 0;
    for (const scenario of SCENARIOS) {
        const spec = scenario(rng);
        const { bytes, labels } = materialize(spec.relPath, spec.template, spec.insertions);
        const abs = join(opts.outDir, spec.relPath);
        mkdirSync(dirname(abs), { recursive: true });
        writeFileSync(abs, bytes);
        const len = Buffer.byteLength(bytes, "utf8");
        totalBytes += len;
        files.push({ relPath: spec.relPath, absPath: abs, bytes: len });
        allLabels.push(...labels);
    }
    writeFileSync(join(opts.outDir, "labels.jsonl"), allLabels.map((l) => JSON.stringify(l)).join("\n") + "\n");
    return { files, labels: allLabels, totalBytes };
}
