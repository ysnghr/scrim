// MCP tool definitions for the Scrim server.
// Each handler: read/exec -> detect -> tokenize via vault -> append audit -> return masked content.

import type { Vault } from "../vault/index.ts";
import type { Policy } from "../policy/index.ts";
import type { EngineConfig } from "../engine/index.ts";

export interface ToolContext {
  policy: Policy;
  engine: EngineConfig;
  vault: Vault;
  auditRoot: string;
}

export async function safe_read(_args: { path: string }, _ctx: ToolContext): Promise<{ content: string }> {
  throw new Error("safe_read: not implemented yet");
}

export async function safe_grep(_args: { pattern: string; path?: string }, _ctx: ToolContext): Promise<{ matches: string[] }> {
  throw new Error("safe_grep: not implemented yet");
}

export async function safe_shell(_args: { command: string; timeoutMs?: number }, _ctx: ToolContext): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  throw new Error("safe_shell: not implemented yet");
}

export async function scrim_status(_args: Record<string, never>, _ctx: ToolContext): Promise<unknown> {
  throw new Error("scrim_status: not implemented yet");
}
