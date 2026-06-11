// Integration tests for the MCP-side ingress pipeline. Exercise processText
// end-to-end and each tool handler with a real on-disk repo. Does not boot the
// MCP transport — that's verified separately by a stdio smoke test.

import { test } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildContext } from "./context.js";
import { processText, BlockedError } from "./process.js";
import {
  safeRead, safeGrep, safeShell, safeWriteToken, scrimStatus, scrimDoctor,
  REQUIRED_DENY_RULES,
} from "./tools.js";
import { tail as auditTail } from "../audit/index.js";

function freshRepo(): string {
  return mkdtempSync(join(tmpdir(), "scrim-mcp-"));
}

function writePolicy(root: string, yaml: string): void {
  mkdirSync(join(root, ".scrim"), { recursive: true });
  writeFileSync(join(root, ".scrim", "policy.yml"), yaml);
}

test("processText redacts secrets and audits each detection", () => {
  const root = freshRepo();
  const ctx = buildContext(root);
  const text = "aws_key = AKIAIOSFODNN7EXAMPL2\ngh = ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

  const { output, detections } = processText(text, "safe_read", ctx);

  assert.equal(detections.length, 2);
  assert.ok(!output.includes("AKIAIOSFODNN7EXAMPL2"), "raw AWS key should be replaced");
  assert.ok(!output.includes("ghp_aaaa"), "raw GitHub PAT should be replaced");
  assert.match(output, /⟦scrim:aws-access-key-id:[a-f0-9]{8}⟧/);
  assert.match(output, /⟦scrim:github-token-classic:[a-f0-9]{8}⟧/);

  const recent = auditTail(root, 10);
  assert.equal(recent.length, 2);
  for (const e of recent) {
    assert.equal(e.action, "redact");
    assert.equal(e.tool, "safe_read");
    assert.match(e.tokenRef!, /^⟦scrim:/);
    assert.match(e.valueHash!, /^[a-f0-9]{12}$/);
  }
});

test("processText respects policy actions: alert leaves content, audits only", () => {
  const root = freshRepo();
  writePolicy(root, "actions:\n  secrets: alert\n");
  const ctx = buildContext(root);
  const text = "aws_key = AKIAIOSFODNN7EXAMPL2";

  const { output, detections } = processText(text, "safe_read", ctx);
  assert.equal(detections.length, 1);
  assert.equal(detections[0]!.action, "alert");
  assert.ok(output.includes("AKIAIOSFODNN7EXAMPL2"), "alert action must NOT replace the value");

  const recent = auditTail(root, 10);
  assert.equal(recent[0]!.action, "alert");
});

test("processText throws BlockedError when policy says block, and audits it", () => {
  const root = freshRepo();
  writePolicy(root, "actions:\n  secrets: block\n");
  const ctx = buildContext(root);
  const text = "aws_key = AKIAIOSFODNN7EXAMPL2";

  assert.throws(() => processText(text, "safe_read", ctx), (err) => err instanceof BlockedError);
  const recent = auditTail(root, 10);
  assert.equal(recent[0]!.action, "block");
});

test("processText passes through with no audit when allow", () => {
  const root = freshRepo();
  writePolicy(root, "actions:\n  secrets: allow\n");
  const ctx = buildContext(root);
  const text = "aws_key = AKIAIOSFODNN7EXAMPL2";

  const { output, detections } = processText(text, "safe_read", ctx);
  assert.ok(output.includes("AKIAIOSFODNN7EXAMPL2"));
  assert.equal(detections.length, 0);
  assert.deepEqual(auditTail(root, 10), []);
});

test("safe_read returns masked file content and detection count", () => {
  const root = freshRepo();
  const target = join(root, "config.yml");
  writeFileSync(
    target,
    "database:\n  host: db.internal\n  password: hunter2-realsecret-abc\nport: 5432\n",
  );
  writePolicy(
    root,
    "tune:\n  internal_domains: ['*.internal']\nactions:\n  internal_hostnames: redact\n",
  );
  const ctx = buildContext(root);

  const res = safeRead({ path: "config.yml" }, ctx);
  assert.equal(res.path, "config.yml");
  assert.ok(res.detections >= 2, `expected detections >= 2, got ${res.detections}`);
  assert.ok(!res.content.includes("hunter2-realsecret-abc"));
  assert.ok(!res.content.includes("db.internal"));
  assert.match(res.content, /port: 5432/);
});

test("safe_read refuses binary files", () => {
  const root = freshRepo();
  const target = join(root, "blob.bin");
  writeFileSync(target, Buffer.from([0x00, 0x01, 0x02, 0x00, 0xff]));
  const ctx = buildContext(root);
  assert.throws(() => safeRead({ path: "blob.bin" }, ctx), /binary/);
});

test("safe_read enforces maxBytes", () => {
  const root = freshRepo();
  const target = join(root, "big.txt");
  writeFileSync(target, "x".repeat(2048));
  const ctx = buildContext(root);
  assert.throws(() => safeRead({ path: "big.txt", maxBytes: 1024 }, ctx), /exceeds maxBytes/);
});

test("safe_read returns blocked outcome when policy blocks", () => {
  const root = freshRepo();
  writePolicy(root, "actions:\n  secrets: block\n");
  writeFileSync(join(root, "secret.env"), "TOKEN=AKIAIOSFODNN7EXAMPL2\n");
  const ctx = buildContext(root);
  const res = safeRead({ path: "secret.env" }, ctx);
  assert.ok(res.blocked, "expected blocked field");
  assert.equal(res.content, "");
});

test("safe_grep redacts matched lines and excludes non-matching lines", () => {
  const root = freshRepo();
  writeFileSync(
    join(root, "a.yml"),
    "name: ok\npassword: hunter2-X9kQ2vWp1aZmL7Tu4N3bR8\n",
  );
  writeFileSync(join(root, "b.yml"), "totally unrelated\n");
  const ctx = buildContext(root);

  const res = safeGrep({ pattern: "password" }, ctx);
  assert.equal(res.matches.length, 1);
  assert.equal(res.matches[0]!.path, "a.yml");
  assert.ok(!res.matches[0]!.text.includes("X9kQ2vWp1aZmL7Tu4N3bR8"));
});

test("safe_grep honors maxMatches and reports truncation", () => {
  const root = freshRepo();
  let body = "";
  for (let i = 0; i < 50; i++) body += `line ${i} match\n`;
  writeFileSync(join(root, "big.txt"), body);
  const ctx = buildContext(root);

  const res = safeGrep({ pattern: "match", maxMatches: 10 }, ctx);
  assert.equal(res.matches.length, 10);
  assert.equal(res.truncated, true);
});

test("safe_shell redacts command stdout", () => {
  const root = freshRepo();
  const ctx = buildContext(root);
  const res = safeShell({ command: "printf 'token=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'" }, ctx);
  assert.equal(res.exitCode, 0);
  assert.ok(!res.stdout.includes("ghp_aaaa"));
  assert.match(res.stdout, /⟦scrim:github-token-classic:/);
  assert.ok(res.detections >= 1);
});

test("safe_write_token: updates the value an existing token resolves to", () => {
  const root = freshRepo();
  const ctx = buildContext(root);

  // Mint a token via the normal redaction path.
  const { output } = processText("aws_key = AKIAIOSFODNN7EXAMPL2", "safe_read", ctx);
  const m = output.match(/⟦scrim:[a-zA-Z0-9_\-]+:[a-f0-9]+⟧/);
  assert.ok(m, "expected a token in masked output");
  const token = m![0];

  const res = safeWriteToken({ token, newValue: "AKIAREPLACEDREPLACED" }, ctx);
  assert.equal(res.token, token);
  assert.match(res.previousValueHash, /^[a-f0-9]{12}$/);
  // Resolving via the vault returns the NEW value.
  assert.equal(ctx.vault.resolve(token), "AKIAREPLACEDREPLACED");
});

test("safe_write_token: rejects an unknown token", () => {
  const root = freshRepo();
  const ctx = buildContext(root);
  assert.throws(
    () => safeWriteToken({ token: "⟦scrim:unknown:deadbeef⟧", newValue: "x" }, ctx),
    /unknown token/,
  );
});

test("safe_write_token: rejects empty newValue", () => {
  const root = freshRepo();
  const ctx = buildContext(root);
  const { output } = processText("aws_key = AKIAIOSFODNN7EXAMPL2", "safe_read", ctx);
  const token = output.match(/⟦scrim:[^⟧]+⟧/)![0];
  assert.throws(() => safeWriteToken({ token, newValue: "" }, ctx), /empty value/);
});

test("safe_write_token: audit entry has no raw values", () => {
  const root = freshRepo();
  const ctx = buildContext(root);
  const { output } = processText("aws_key = AKIAIOSFODNN7EXAMPL2", "safe_read", ctx);
  const token = output.match(/⟦scrim:[^⟧]+⟧/)![0];
  safeWriteToken({ token, newValue: "AKIAREPLACEDREPLACED" }, ctx);

  const entries = auditTail(root, 10);
  const rewrite = entries.find((e) => e.action === "rewrite");
  assert.ok(rewrite, "expected a rewrite entry");
  const raw = JSON.stringify(rewrite);
  assert.ok(!raw.includes("AKIAIOSFODNN7EXAMPL2"), "audit must not contain prior value");
  assert.ok(!raw.includes("AKIAREPLACEDREPLACED"), "audit must not contain new value");
  assert.match(rewrite!.valueHash!, /^[a-f0-9]{12}$/);
});

test("scrim_doctor: deny-rules-present fails when settings.json is absent", () => {
  const root = freshRepo();
  const ctx = buildContext(root);
  const report = scrimDoctor(ctx);
  const denyCheck = report.checks.find((c) => c.name === "deny-rules-present");
  assert.ok(denyCheck, "expected a deny-rules-present check");
  assert.equal(denyCheck!.status, "fail");
  assert.equal(report.ok, false);
});

test("scrim_doctor: deny-rules-present passes when all required rules are set", () => {
  const root = freshRepo();
  mkdirSync(join(root, ".claude"), { recursive: true });
  writeFileSync(
    join(root, ".claude", "settings.json"),
    JSON.stringify({ permissions: { deny: REQUIRED_DENY_RULES } }),
  );
  const ctx = buildContext(root);
  const report = scrimDoctor(ctx);
  const denyCheck = report.checks.find((c) => c.name === "deny-rules-present");
  assert.equal(denyCheck!.status, "pass");
});

test("scrim_doctor: deny-rules-present reports which rules are missing", () => {
  const root = freshRepo();
  mkdirSync(join(root, ".claude"), { recursive: true });
  // Only include the first three rules.
  writeFileSync(
    join(root, ".claude", "settings.json"),
    JSON.stringify({ permissions: { deny: REQUIRED_DENY_RULES.slice(0, 3) } }),
  );
  const ctx = buildContext(root);
  const report = scrimDoctor(ctx);
  const denyCheck = report.checks.find((c) => c.name === "deny-rules-present");
  assert.equal(denyCheck!.status, "fail");
  assert.match(denyCheck!.detail, /3 of 6 recommended deny rules missing/);
  // Each missing rule appears in the detail.
  for (const r of REQUIRED_DENY_RULES.slice(3)) {
    assert.ok(denyCheck!.detail.includes(r), `expected missing rule in detail: ${r}`);
  }
});

test("scrim_doctor: vault-healthy warns when near cap", () => {
  const root = freshRepo();
  // Tight cap so it's easy to push over 90%.
  mkdirSync(join(root, ".scrim"), { recursive: true });
  writeFileSync(join(root, ".scrim", "policy.yml"), "vault:\n  max_entries: 10\n");
  const ctx = buildContext(root);
  for (let i = 0; i < 9; i++) ctx.vault.tokenize(`v-${i}`, "secrets");
  const report = scrimDoctor(ctx);
  const v = report.checks.find((c) => c.name === "vault-healthy");
  assert.equal(v!.status, "warn");
  assert.match(v!.detail, /90%/);
});

test("scrim_status returns policy summary, vault stats, and audit counts", () => {
  const root = freshRepo();
  const ctx = buildContext(root);
  safeShell({ command: "printf 'k=AKIAIOSFODNN7EXAMPL2'" }, ctx);

  const status = scrimStatus(ctx);
  assert.equal(status.policy.version, 1);
  assert.equal(status.policy.failClosed, true);
  assert.equal(status.policy.detection.gitleaks, true);
  assert.ok(status.vault.size >= 1);
  assert.ok(status.audit.total >= 1);
  assert.ok((status.audit.byAction["redact"] ?? 0) >= 1);
});
