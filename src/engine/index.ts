// Detection engine entrypoint.
// Composes the configured detection sources (secrets, fast PII regex, optional Presidio, repo-tuned)
// and returns a list of spans { start, end, class, ruleId } for an input string.

export interface DetectionSpan {
  start: number;
  end: number;
  class: string;
  ruleId: string;
}

export interface EngineConfig {
  gitleaks: boolean;
  fastPiiRegex: boolean;
  presidio: boolean;
  tunedEnvKeys: string[];
  tunedInternalDomains: string[];
  tunedCustomPatterns: { name: string; regex: RegExp; class: string }[];
  allowlist: Set<string>;
}

export function detect(_text: string, _cfg: EngineConfig): DetectionSpan[] {
  throw new Error("detect: not implemented yet");
}
