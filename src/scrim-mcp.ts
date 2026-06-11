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
  scrimStatus,
} from "./mcp/tools.js";

const repoRoot = process.cwd();
const ctx = buildContext(repoRoot);

const server = new McpServer({ name: "scrim", version: "0.0.1" });

server.registerTool(
  "safe_read",
  {
    title: "safe_read",
    description:
      "Read a file with secrets and PII reversibly tokenized. Use for any config-like file (.env*, *.tfvars, *.pem, config.{json,yml,yaml,toml}, settings.py, files under secrets/**). The model sees tokens like ⟦scrim:db_password:a1b2c3⟧; the PreToolUse hook restores real values before writes.",
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
      "Grep across files with secrets and PII reversibly tokenized in the matched lines. Pass a regex via `pattern` (JS syntax) and an optional `path` (file or directory; defaults to repo root).",
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
      "Run a shell command and return its output with secrets and PII reversibly tokenized. Prefer this over the native Bash for commands whose output frequently contains credentials (env, printenv, kubectl get secret, docker inspect, git remote -v, anything printing a connection string).",
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
