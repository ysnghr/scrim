// Shared state for the MCP server: policy, engine config, vault. Built once at
// server start. The MCP transport is single-process and single-threaded enough
// that no locking is required across handlers; the vault file is the only
// cross-process artifact and its writes are already atomic.
import { buildEngineConfig } from "../engine/index.js";
import { loadPolicy, toEngineInput } from "../policy/index.js";
import { openVault } from "../vault/index.js";
export function buildContext(repoRoot) {
    const policy = loadPolicy(repoRoot);
    const engine = buildEngineConfig(toEngineInput(policy), repoRoot);
    const vault = openVault(repoRoot);
    return { repoRoot, policy, engine, vault };
}
