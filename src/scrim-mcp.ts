// Entrypoint for the Scrim MCP server.
//
// Compiled to bin/scrim-mcp.js and launched via .mcp.json. Talks MCP over
// stdio, registers four tools (safe_read, safe_grep, safe_shell, scrim_status),
// and shares a single Context (policy + engine + vault) across handler calls.

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { buildContext } from "./mcp/context.js";
import {
  safeRead,
  safeGrep,
  safeShell,
  safeWriteToken,
  scrimStatus,
  scrimDoctor,
} from "./mcp/tools.js";

const repoRoot = process.cwd();
const ctx = buildContext(repoRoot);

const server = new McpServer({ name: "scrim", version: "0.0.1" });

server.registerTool(
  "safe_read",
  {
    title: "safe_read",
    description:
      "Read a file with secrets and PII reversibly tokenized. You MUST use this tool — NOT the native Read — for any file matching: .env*, *.tfvars, *.pem, secrets/**, config.{json,yml,yaml,toml}, settings.py, *.tfstate, **/credentials*, any file containing connection strings. Native Read on these paths is typically denied by the project's permissions config; calling it will fail. safe_read returns the same content but with secrets replaced by tokens like ⟦scrim:db_password:a1b2c3⟧. The PreToolUse hook restores real values before any Write touches disk, so the file ends up byte-correct. Use native Read for everything else (source code, build output, README files, etc.).",
    inputSchema: {
      path: z.string().describe("File path, absolute or relative to repo root"),
      maxBytes: z.number().int().positive().optional()
        .describe("Refuse files larger than this; default 2_000_000"),
    },
  },
  async (args) => {
    const result = safeRead(args, ctx);
    return { content: [{ type: "text", text: JSON.stringify(result) }] };
  },
);

server.registerTool(
  "safe_grep",
  {
    title: "safe_grep",
    description:
      "Grep across files with secrets and PII reversibly tokenized in matched lines. You MUST use this — NOT native Bash with grep/rg/ripgrep — whenever the search may cross config-like files (.env*, *.tfvars, *.pem, secrets/**, config.*, settings.py). Returns matched lines with secrets replaced by tokens. Pass a regex via `pattern` (JS syntax) and an optional `path` (file or directory; defaults to repo root).",
    inputSchema: {
      pattern: z.string().describe("JS-flavored regular expression"),
      path: z.string().optional().describe("File or directory to search; default is repo root"),
      flags: z.string().optional().describe("Regex flags (e.g. 'i'); 'g' is always added"),
      maxMatches: z.number().int().positive().optional()
        .describe("Cap on returned matches; default 200"),
    },
  },
  async (args) => {
    const result = safeGrep(args, ctx);
    return { content: [{ type: "text", text: JSON.stringify(result) }] };
  },
);

server.registerTool(
  "safe_shell",
  {
    title: "safe_shell",
    description:
      "Run a shell command and return stdout/stderr with secrets and PII reversibly tokenized. You MUST use this — NOT the native Bash — for any command whose output may contain credentials: env, printenv, set (no args), kubectl get/describe/edit/view secret, docker inspect, docker compose config, git remote -v, aws configure, gcloud auth print-access-token, cat /proc/*/environ, anything printing a connection string. The bash-guard hook DENIES these commands when run via native Bash and instructs you to call safe_shell instead. Use native Bash for everything else (ls, git status, npm test, etc.).",
    inputSchema: {
      command: z.string().describe("Shell command to execute"),
      timeoutMs: z.number().int().positive().optional()
        .describe("Kill the command after this many ms; default 30_000"),
      cwd: z.string().optional().describe("Working directory; default is repo root"),
    },
  },
  async (args) => {
    const result = safeShell(args, ctx);
    return { content: [{ type: "text", text: JSON.stringify(result) }] };
  },
);

server.registerTool(
  "safe_write_token",
  {
    title: "safe_write_token",
    description:
      "Change the value that an existing Scrim token resolves to. Use this when you need to MODIFY a value that was redacted on read — e.g. rotating a password, updating a secret, changing a URL inside a tokenized connection string. The token slug stays the same, so every place that token appears in your context (and in any files you write back) will resolve to the new value. WARNING: this is a single global update — if the same token appears in multiple files, all of them will get the new value on next write. The token MUST already exist in the vault (it was minted by a prior safe_read/safe_grep/safe_shell); calling this with an unknown token is an error.",
    inputSchema: {
      token: z.string().describe("The existing ⟦scrim:class:id⟧ token to update"),
      newValue: z.string().min(1).describe("The new value the token should resolve to"),
    },
  },
  async (args) => {
    const result = safeWriteToken(args, ctx);
    return { content: [{ type: "text", text: JSON.stringify(result) }] };
  },
);

server.registerTool(
  "scrim_status",
  {
    title: "scrim_status",
    description:
      "Return active detection rules, vault size, recent detections, and hook registration status. Used by /scrim:status.",
    inputSchema: {},
  },
  async () => {
    const result = scrimStatus(ctx);
    return { content: [{ type: "text", text: JSON.stringify(result) }] };
  },
);

server.registerTool(
  "scrim_doctor",
  {
    title: "scrim_doctor",
    description:
      "Run health checks: are the recommended deny rules present in .claude/settings.json, is the policy loadable, is the vault healthy and not near its LRU cap, are the hook binaries present, is the Presidio sidecar reachable (if enabled)? Used by /scrim:doctor. Run this after install or whenever Scrim seems not to be intercepting reads.",
    inputSchema: {},
  },
  async () => {
    const result = scrimDoctor(ctx);
    return { content: [{ type: "text", text: JSON.stringify(result) }] };
  },
);

async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  // Surface the failure on stderr so the user sees it in /mcp logs.
  // We never write secrets here — only error messages.
  console.error("scrim-mcp: fatal:", err instanceof Error ? err.stack ?? err.message : err);
  process.exit(1);
});
