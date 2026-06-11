// Loads and validates .scrim/policy.yml; merges with the shipped default policy.
// Exposes a typed Policy that the engine, MCP server, and hooks consume.

export type Action = "redact" | "block" | "alert" | "allow";

export interface Policy {
  version: 1;
  actions: Record<string, Action>;       // class -> action
  detection: {
    gitleaks: boolean;
    presidio: boolean;
    fastPiiRegex: boolean;
  };
  tune: {
    envKeysFrom: string[];
    internalDomains: string[];
    customPatterns: { name: string; regex: string; class: string }[];
  };
  failClosed: boolean;
  allow: string[];
}

export function load(_repoRoot: string, _pluginRoot: string): Policy {
  throw new Error("policy.load: not implemented yet");
}
