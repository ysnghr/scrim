// Hook logic tests. Cover the pure functions plus an end-to-end check of the
// compiled entrypoint scripts via spawn so we exercise the stdin/stdout contract
// Claude Code will use.

import { test } from "node:test";
import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { openVault } from "../vault/index.js";
import { detokenize, rewriteStrings } from "./detokenize.js";
import { decideBash } from "./bash-guard.js";

const PLUGIN_ROOT = resolve(import.meta.dirname, "..", "..");
const DETOKENIZE_BIN = join(PLUGIN_ROOT, "bin", "scrim-detokenize.js");
const BASH_GUARD_BIN = join(PLUGIN_ROOT, "bin", "scrim-bash-guard.js");

function freshRepo(): string {
  return mkdtempSync(join(tmpdir(), "scrim-hook-"));
}

// ---------------- detokenize (pure logic) ----------------

test("detokenize: allows untouched tool_input when there are no tokens", () => {
  const vault = { resolve: () => null };
  const r = detokenize(
    { tool_name: "Write", tool_input: { file_path: "x.txt", content: "hello world" } },
    vault,
  );
  assert.equal(r.output.hookSpecificOutput.permissionDecision, "allow");
  assert.equal(r.output.hookSpecificOutput.updatedInput, undefined);
  assert.equal(r.stats.replaced, 0);
  assert.deepEqual(r.stats.missing, []);
});

test("detokenize: rewrites string leaves and returns updatedInput", () => {
  const vault = { resolve: (t: string) => (t === "⟦scrim:db_password:aaaa1111⟧" ? "hunter2" : null) };
  const r = detokenize(
    {
      tool_name: "Write",
      tool_input: {
        file_path: "config.yml",
        content: "password: ⟦scrim:db_password:aaaa1111⟧",
      },
    },
    vault,
  );
  assert.equal(r.output.hookSpecificOutput.permissionDecision, "allow");
  assert.equal(r.stats.replaced, 1);
  const updated = r.output.hookSpecificOutput.updatedInput as { content: string };
  assert.equal(updated.content, "password: hunter2");
});

test("detokenize: walks nested arrays (MultiEdit edits[])", () => {
  const vault = { resolve: (t: string) => (t === "⟦scrim:secrets:aaaa1111⟧" ? "AKIA-real" : null) };
  const r = detokenize(
    {
      tool_name: "MultiEdit",
      tool_input: {
        file_path: "x.yml",
        edits: [
          { old_string: "key: ⟦scrim:secrets:aaaa1111⟧", new_string: "key: ⟦scrim:secrets:aaaa1111⟧" },
        ],
      },
    },
    vault,
  );
  assert.equal(r.stats.replaced, 2);
  const updated = r.output.hookSpecificOutput.updatedInput as { edits: { old_string: string; new_string: string }[] };
  assert.equal(updated.edits[0]!.old_string, "key: AKIA-real");
  assert.equal(updated.edits[0]!.new_string, "key: AKIA-real");
});

test("detokenize: fail-closed when any token cannot be resolved", () => {
  const vault = { resolve: () => null };
  const r = detokenize(
    { tool_name: "Write", tool_input: { file_path: "x", content: "x ⟦scrim:secrets:deadbeef⟧" } },
    vault,
  );
  assert.equal(r.output.hookSpecificOutput.permissionDecision, "deny");
  assert.match(r.output.hookSpecificOutput.permissionDecisionReason!, /could not be resolved/);
  assert.deepEqual(r.stats.missing, ["⟦scrim:secrets:deadbeef⟧"]);
});

test("rewriteStrings: returns original (no copy) when value has no tokens", () => {
  const vault = { resolve: () => null };
  const stats = { replaced: 0, missing: [] as string[] };
  const value = "no tokens here";
  assert.equal(rewriteStrings(value, vault, stats), value);
});

// ---------------- bash-guard (pure logic) ----------------

test("bash-guard: allows ordinary commands", () => {
  for (const cmd of ["ls -la", "git status", "npm test", "rg pattern src/", "node script.js"]) {
    const { output, matched } = decideBash({ tool_input: { command: cmd } });
    assert.equal(output.hookSpecificOutput.permissionDecision, "allow", `expected allow for: ${cmd}`);
    assert.equal(matched, undefined);
  }
});

test("bash-guard: denies env / printenv / kubectl get secret / docker inspect / git remote -v", () => {
  const denied = [
    "env",
    "env | grep PATH",
    "printenv HOME",
    "kubectl get secret my-secret -o yaml",
    "kubectl describe secret foo",
    "docker inspect mycontainer",
    "git remote -v",
    "git remote show origin",
    "aws configure list",
    "gcloud auth print-access-token",
    "docker compose config",
  ];
  for (const cmd of denied) {
    const { output, matched } = decideBash({ tool_input: { command: cmd } });
    assert.equal(output.hookSpecificOutput.permissionDecision, "deny", `expected deny for: ${cmd}`);
    assert.ok(matched, `expected matched rule for: ${cmd}`);
    assert.match(output.hookSpecificOutput.permissionDecisionReason!, /safe_shell/);
  }
});

test("bash-guard: catches env / printenv inside pipelines and chains", () => {
  for (const cmd of ["foo && env", "ls; printenv", "(env | head)"]) {
    const { output } = decideBash({ tool_input: { command: cmd } });
    assert.equal(output.hookSpecificOutput.permissionDecision, "deny", `expected deny for: ${cmd}`);
  }
});

test("bash-guard: does NOT deny lookalikes (envoy, environment, etc.)", () => {
  for (const cmd of ["envoy --version", "echo $environment", "kubectl get pods"]) {
    const { output } = decideBash({ tool_input: { command: cmd } });
    assert.equal(output.hookSpecificOutput.permissionDecision, "allow", `expected allow for: ${cmd}`);
  }
});

test("bash-guard: empty command is allowed", () => {
  const { output } = decideBash({ tool_input: {} });
  assert.equal(output.hookSpecificOutput.permissionDecision, "allow");
});

// ---------------- entrypoint scripts (stdio contract) ----------------

test("scrim-detokenize.js: rewrites tool_input via stdin/stdout", () => {
  const root = freshRepo();
  const vault = openVault(root);
  const token = vault.tokenize("hunter2-realpw", "db_password");

  const payload = {
    hook_event_name: "PreToolUse",
    tool_name: "Write",
    tool_input: { file_path: "config.yml", content: `password: ${token}\n` },
    cwd: root,
  };

  const res = spawnSync("node", [DETOKENIZE_BIN], {
    input: JSON.stringify(payload),
    encoding: "utf8",
    cwd: root,
  });
  assert.equal(res.status, 0, `stderr: ${res.stderr}`);
  const out = JSON.parse(res.stdout);
  assert.equal(out.hookSpecificOutput.permissionDecision, "allow");
  assert.equal(out.hookSpecificOutput.updatedInput.content, "password: hunter2-realpw\n");
});

test("scrim-detokenize.js: denies when a token can't be resolved", () => {
  const root = freshRepo();
  openVault(root); // create vault but don't add the token
  const payload = {
    hook_event_name: "PreToolUse",
    tool_name: "Write",
    tool_input: { file_path: "x.txt", content: "leak: ⟦scrim:secrets:deadbeef⟧" },
    cwd: root,
  };
  const res = spawnSync("node", [DETOKENIZE_BIN], {
    input: JSON.stringify(payload),
    encoding: "utf8",
  });
  assert.equal(res.status, 0);
  const out = JSON.parse(res.stdout);
  assert.equal(out.hookSpecificOutput.permissionDecision, "deny");
  assert.match(out.hookSpecificOutput.permissionDecisionReason, /could not be resolved/);
});

test("scrim-bash-guard.js: denies risky and allows benign", () => {
  const root = freshRepo();
  const riskyPayload = {
    hook_event_name: "PreToolUse",
    tool_name: "Bash",
    tool_input: { command: "env | grep AWS" },
    cwd: root,
  };
  const safePayload = {
    hook_event_name: "PreToolUse",
    tool_name: "Bash",
    tool_input: { command: "ls -la" },
    cwd: root,
  };

  const r1 = spawnSync("node", [BASH_GUARD_BIN], { input: JSON.stringify(riskyPayload), encoding: "utf8" });
  assert.equal(r1.status, 0, `stderr: ${r1.stderr}`);
  const out1 = JSON.parse(r1.stdout);
  assert.equal(out1.hookSpecificOutput.permissionDecision, "deny");

  const r2 = spawnSync("node", [BASH_GUARD_BIN], { input: JSON.stringify(safePayload), encoding: "utf8" });
  assert.equal(r2.status, 0);
  const out2 = JSON.parse(r2.stdout);
  assert.equal(out2.hookSpecificOutput.permissionDecision, "allow");
});
