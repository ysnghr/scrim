// Shared state for the MCP server: policy, engine config, vault. Built once at
// server start. The MCP transport is single-process and single-threaded enough
// that no locking is required across handlers; the vault file is the only
// cross-process artifact and its writes are already atomic.

import { buildEngineConfig, type EngineConfig } from "../engine/index.js";
import { loadPolicy, toEngineInput, type Policy } from "../policy/index.js";
import { openVault, type Vault } from "../vault/index.js";

export interface Context {
  repoRoot: string;
  policy: Policy;
  engine: EngineConfig;
  vault: Vault;
}

export function buildContext(repoRoot: string): Context {
  const policy = loadPolicy(repoRoot);
  const engine = buildEngineConfig(toEngineInput(policy), repoRoot);
  const vault = openVault(repoRoot, { maxEntries: policy.vault.maxEntries });
  return { repoRoot, policy, engine, vault };
}
