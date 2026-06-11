// Audit log tests. Focus on the value-free invariant, ordering, and tail.

import { test } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync, readFileSync, existsSync, appendFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { append, tail, hashValue, summary, logPathFor } from "./index.js";

function freshRepo(): string {
  return mkdtempSync(join(tmpdir(), "scrim-audit-"));
}

test("append then tail returns the entry with auto-filled ts", () => {
  const root = freshRepo();
  append(root, { ruleId: "aws-access-key-id", tool: "safe_read", action: "redact" });
  const entries = tail(root, 10);
  assert.equal(entries.length, 1);
  assert.equal(entries[0]!.ruleId, "aws-access-key-id");
  assert.equal(entries[0]!.tool, "safe_read");
  assert.equal(entries[0]!.action, "redact");
  assert.match(entries[0]!.ts!, /^\d{4}-\d{2}-\d{2}T/);
});

test("tail preserves chronological order", () => {
  const root = freshRepo();
  for (let i = 0; i < 5; i++) {
    append(root, {
      ts: new Date(2026, 0, 1, 0, 0, i).toISOString(),
      ruleId: `rule-${i}`,
      tool: "safe_read",
      action: "redact",
    });
  }
  const entries = tail(root, 3);
  assert.deepEqual(entries.map((e) => e.ruleId), ["rule-2", "rule-3", "rule-4"]);
});

test("tail handles a missing log file", () => {
  const root = freshRepo();
  assert.deepEqual(tail(root, 5), []);
});

test("audit log never serializes a value field", () => {
  const root = freshRepo();
  // Caller mistakenly passes a value — the sanitizer must strip it.
  const entry = {
    ruleId: "aws-access-key-id",
    tool: "safe_read",
    action: "redact",
    value: "AKIAIOSFODNN7EXAMPL2",
    secret: "shouldnt be here",
  } as unknown as Parameters<typeof append>[1];
  append(root, entry);

  const raw = readFileSync(logPathFor(root), "utf8");
  assert.ok(!raw.includes("AKIAIOSFODNN7EXAMPL2"), "raw value leaked into audit log");
  assert.ok(!raw.includes("shouldnt be here"), "extra key leaked into audit log");
});

test("audit log lines are valid JSON, one per line", () => {
  const root = freshRepo();
  append(root, { ruleId: "a", tool: "safe_read", action: "redact" });
  append(root, { ruleId: "b", tool: "Bash", action: "block" });
  const raw = readFileSync(logPathFor(root), "utf8");
  const lines = raw.split("\n").filter(Boolean);
  assert.equal(lines.length, 2);
  for (const line of lines) {
    assert.doesNotThrow(() => JSON.parse(line));
  }
});

test("hashValue is stable for the same value within a repo and salted across repos", () => {
  const repoA = freshRepo();
  const repoB = freshRepo();
  const h1 = hashValue(repoA, "AKIAIOSFODNN7EXAMPL2");
  const h2 = hashValue(repoA, "AKIAIOSFODNN7EXAMPL2");
  const h3 = hashValue(repoB, "AKIAIOSFODNN7EXAMPL2");
  assert.equal(h1, h2);
  assert.notEqual(h1, h3);
  assert.match(h1, /^[a-f0-9]{12}$/);
});

test("hashValue length is 12 hex chars and changes with input", () => {
  const root = freshRepo();
  const h1 = hashValue(root, "alpha");
  const h2 = hashValue(root, "beta");
  assert.notEqual(h1, h2);
  assert.equal(h1.length, 12);
});

test("oversized entries are rejected to preserve PIPE_BUF atomicity", () => {
  const root = freshRepo();
  const huge = "x".repeat(5000);
  assert.throws(
    () => append(root, {
      ruleId: "a", tool: "safe_read", action: "redact",
      context: { blob: huge },
    }),
    /audit entry too large/,
  );
});

test("summary counts entries by action", () => {
  const root = freshRepo();
  append(root, { ruleId: "a", tool: "safe_read", action: "redact" });
  append(root, { ruleId: "b", tool: "safe_read", action: "redact" });
  append(root, { ruleId: "c", tool: "Bash", action: "block" });
  append(root, { ruleId: "d", tool: "safe_grep", action: "alert" });

  const s = summary(root);
  assert.equal(s.total, 4);
  assert.equal(s.byAction.redact, 2);
  assert.equal(s.byAction.block, 1);
  assert.equal(s.byAction.alert, 1);
});

test("malformed lines are skipped rather than crashing tail", () => {
  const root = freshRepo();
  append(root, { ruleId: "a", tool: "safe_read", action: "redact" });
  // Inject a malformed line directly to the log.
  appendFileSync(logPathFor(root), "not-json\n");
  append(root, { ruleId: "b", tool: "safe_read", action: "redact" });

  const entries = tail(root, 10);
  assert.equal(entries.length, 2);
  assert.deepEqual(entries.map((e) => e.ruleId), ["a", "b"]);
});

test("salt file is created with restrictive mode", { skip: process.platform === "win32" }, () => {
  const root = freshRepo();
  hashValue(root, "anything");
  const saltPath = join(root, ".scrim", "audit", "salt");
  assert.ok(existsSync(saltPath));
  const stat = readFileSync(saltPath);
  assert.equal(stat.length, 16);
});
