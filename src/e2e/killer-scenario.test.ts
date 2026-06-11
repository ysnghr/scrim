// End-to-end test of the README's "killer scenario":
//   1. A config file on disk contains a real database password.
//   2. The MCP server's safe_read returns the file with the password tokenized.
//   3. The agent "writes the file back" unchanged (still containing the token).
//   4. The PreToolUse detokenize hook restores the real password before the
//      write hits disk.
//
// Both the MCP server and the detokenize hook are exercised as real child
// processes over stdio — this is the integration contract Claude Code uses.

import { test } from "node:test";
import { strict as assert } from "node:assert";
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { tail as auditTail } from "../audit/index.js";

const PLUGIN_ROOT = resolve(import.meta.dirname, "..", "..");
const MCP_BIN = join(PLUGIN_ROOT, "bin", "scrim-mcp.js");
const DETOKENIZE_BIN = join(PLUGIN_ROOT, "bin", "scrim-detokenize.js");

interface MCPClient {
  call(method: string, params?: unknown): Promise<unknown>;
  notify(method: string, params?: unknown): void;
  close(): Promise<void>;
}

function startMcp(cwd: string): MCPClient {
  const child = spawn("node", [MCP_BIN], {
    cwd,
    stdio: ["pipe", "pipe", "pipe"],
    env: { ...process.env, SCRIM_PLUGIN_ROOT: PLUGIN_ROOT },
  });

  let buf = "";
  const pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();
  let nextId = 1;

  child.stdout.setEncoding("utf8");
  child.stdout.on("data", (chunk: string) => {
    buf += chunk;
    let nl: number;
    while ((nl = buf.indexOf("\n")) !== -1) {
      const line = buf.slice(0, nl);
      buf = buf.slice(nl + 1);
      if (!line.trim()) continue;
      try {
        const msg = JSON.parse(line) as { id?: number; result?: unknown; error?: { message: string } };
        if (typeof msg.id === "number" && pending.has(msg.id)) {
          const p = pending.get(msg.id)!;
          pending.delete(msg.id);
          if (msg.error) p.reject(new Error(msg.error.message));
          else p.resolve(msg.result);
        }
      } catch {
        // ignore non-JSON-RPC lines
      }
    }
  });
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (s: string) => {
    if (process.env["E2E_DEBUG"]) process.stderr.write(`[mcp stderr] ${s}`);
  });

  function send(payload: unknown): void {
    child.stdin.write(JSON.stringify(payload) + "\n");
  }

  return {
    call(method, params) {
      const id = nextId++;
      const promise = new Promise((resolve, reject) => pending.set(id, { resolve, reject }));
      send({ jsonrpc: "2.0", id, method, params });
      return promise;
    },
    notify(method, params) {
      send({ jsonrpc: "2.0", method, params });
    },
    close() {
      child.stdin.end();
      return new Promise((resolve) => child.on("exit", () => resolve()));
    },
  };
}

interface CallToolResult {
  content: { type: string; text: string }[];
}

async function callTool(client: MCPClient, name: string, args: Record<string, unknown>): Promise<unknown> {
  const result = (await client.call("tools/call", { name, arguments: args })) as CallToolResult;
  const text = result.content[0]?.text ?? "";
  return JSON.parse(text);
}

test("killer scenario: safe_read tokenizes, detokenize hook restores byte-for-byte", async () => {
  const root = mkdtempSync(join(tmpdir(), "scrim-e2e-"));

  // 1) on-disk config with a real password
  const realPassword = "X9kQ2vWp1aZmL7Tu4N3bR8";
  const original =
    "database:\n" +
    "  host: db.example.com\n" +
    `  password: ${realPassword}\n` +
    "  port: 5432\n";
  writeFileSync(join(root, "config.yml"), original);

  // 2) MCP boot + safe_read
  const mcp = startMcp(root);
  await mcp.call("initialize", {
    protocolVersion: "2024-11-05",
    capabilities: {},
    clientInfo: { name: "e2e", version: "0" },
  });
  mcp.notify("notifications/initialized");

  const readResult = (await callTool(mcp, "safe_read", { path: "config.yml" })) as {
    content: string;
    detections: number;
  };
  assert.ok(readResult.detections >= 1, "expected at least one detection");
  assert.ok(!readResult.content.includes(realPassword), "raw password leaked into masked content");
  assert.match(readResult.content, /⟦scrim:[a-zA-Z0-9_\-]+:[a-f0-9]+⟧/);

  await mcp.close();

  // 3) detokenize hook: agent "writes the file back" with tokens intact
  const hookPayload = {
    hook_event_name: "PreToolUse",
    tool_name: "Write",
    tool_input: { file_path: "config.yml", content: readResult.content },
    cwd: root,
  };
  const hookRes = spawnSync("node", [DETOKENIZE_BIN], {
    input: JSON.stringify(hookPayload),
    encoding: "utf8",
  });
  assert.equal(hookRes.status, 0, `detokenize stderr: ${hookRes.stderr}`);
  const hookOut = JSON.parse(hookRes.stdout) as {
    hookSpecificOutput: {
      permissionDecision: string;
      updatedInput?: { content?: string };
    };
  };
  assert.equal(hookOut.hookSpecificOutput.permissionDecision, "allow");
  const restored = hookOut.hookSpecificOutput.updatedInput?.content;
  assert.equal(restored, original, "restored content must equal original byte-for-byte");

  // 4) audit log shows both ingress (redact) and egress (restore) entries
  const entries = auditTail(root, 20);
  const actions = entries.map((e) => e.action);
  assert.ok(actions.includes("redact"), `expected a redact entry, got ${JSON.stringify(actions)}`);
  assert.ok(actions.includes("restore"), `expected a restore entry, got ${JSON.stringify(actions)}`);
  for (const e of entries) {
    assert.ok(JSON.stringify(e).indexOf(realPassword) === -1, "audit log must not contain the raw value");
  }
});

test("killer scenario: detokenize denies a write that contains an unknown token", async () => {
  const root = mkdtempSync(join(tmpdir(), "scrim-e2e-"));
  // No prior safe_read — vault is empty. Any token must be unresolvable.
  const payload = {
    hook_event_name: "PreToolUse",
    tool_name: "Write",
    tool_input: { file_path: "config.yml", content: "password: ⟦scrim:secrets:deadbeef⟧\n" },
    cwd: root,
  };
  const res = spawnSync("node", [DETOKENIZE_BIN], { input: JSON.stringify(payload), encoding: "utf8" });
  assert.equal(res.status, 0);
  const out = JSON.parse(res.stdout) as {
    hookSpecificOutput: { permissionDecision: string; permissionDecisionReason: string };
  };
  assert.equal(out.hookSpecificOutput.permissionDecision, "deny");
  assert.match(out.hookSpecificOutput.permissionDecisionReason, /could not be resolved/);
});

test("plugin binaries exist after build", () => {
  // Sanity: hooks.json and .mcp.json both reference these paths.
  for (const p of [
    MCP_BIN,
    DETOKENIZE_BIN,
    join(PLUGIN_ROOT, "bin", "scrim-bash-guard.js"),
    join(PLUGIN_ROOT, "bin", "scrim-stop.js"),
  ]) {
    assert.ok(existsSync(p), `missing build artifact: ${p}`);
  }
});

test("plugin manifests reference valid paths", () => {
  const mcpJson = JSON.parse(readFileSync(join(PLUGIN_ROOT, ".mcp.json"), "utf8")) as {
    mcpServers: Record<string, { command: string; args: string[] }>;
  };
  const args = mcpJson.mcpServers["scrim"]!.args;
  const argPath = args[0]!.replace("${CLAUDE_PLUGIN_ROOT}", PLUGIN_ROOT);
  assert.ok(existsSync(argPath), `.mcp.json points at missing file: ${argPath}`);

  const hooksJson = JSON.parse(readFileSync(join(PLUGIN_ROOT, "hooks", "hooks.json"), "utf8")) as {
    hooks: {
      PreToolUse: { hooks: { command: string }[] }[];
      Stop?: { hooks: { command: string }[] }[];
    };
  };
  const allHookGroups = [
    ...(hooksJson.hooks.PreToolUse ?? []),
    ...(hooksJson.hooks.Stop ?? []),
  ];
  for (const matcher of allHookGroups) {
    for (const h of matcher.hooks) {
      // command is "node ${CLAUDE_PLUGIN_ROOT}/bin/X.js"; pull out the .js path.
      const m = h.command.match(/\$\{CLAUDE_PLUGIN_ROOT\}\/(\S+)/);
      assert.ok(m, `unparseable hook command: ${h.command}`);
      const p = join(PLUGIN_ROOT, m![1]!);
      assert.ok(existsSync(p), `hooks.json points at missing file: ${p}`);
    }
  }
});
