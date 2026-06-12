// Detection engine entrypoint.
//
// Composes the enabled detection sources into a single `detect(text)` call.
// Output is a non-overlapping, sorted list of DetectionSpans the caller can
// hand to the vault for tokenization.
//
// Fail-closed: detectors that throw are caught and re-thrown here. The caller
// (MCP server) translates that into a rejected tool call rather than returning
// raw content. Presidio is the exception — it is opt-in and additive and only
// degrades coverage on failure (see presidio.ts).

import { detectSecrets } from "./secrets.js";
import { detectFastPii } from "./pii.js";
import { detectTuned, parseEnvKeys, globToHostRegex, type TunedConfig } from "./tuned.js";
import { detectPresidio } from "./presidio.js";
import { mergeSpans, type DetectionSpan } from "./spans.js";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

export type { DetectionSpan } from "./spans.js";

export interface EngineConfig {
  gitleaks: boolean;
  fastPiiRegex: boolean;
  presidio: boolean;
  presidioCommand?: string;
  tuned: TunedConfig;
  allowlist: Set<string>;
  // Shannon-entropy threshold for the generic-credential-assignment rule.
  // Lower → more recall, more FPs. Default in policy is 2.7.
  genericCredentialEntropy: number;
}

export interface EngineBuildInput {
  detection: {
    gitleaks: boolean;
    presidio: boolean;
    fastPiiRegex: boolean;
    entropy?: { genericCredential?: number };
  };
  tune: {
    envKeysFrom: string[];
    internalDomains: string[];
    customPatterns: { name: string; regex: string; class: string }[];
  };
  allow: string[];
  presidioCommand?: string;
}

// Build an EngineConfig from a parsed policy and the repo root.
// Reads .env.example-style files referenced by `tune.envKeysFrom`. Files that
// don't exist are skipped silently — they're hints, not requirements.
export function buildEngineConfig(input: EngineBuildInput, repoRoot: string): EngineConfig {
  const envKeys = new Set<string>();
  for (const rel of input.tune.envKeysFrom) {
    try {
      const content = readFileSync(resolve(repoRoot, rel), "utf8");
      for (const k of parseEnvKeys(content)) envKeys.add(k);
    } catch {
      // missing file — ignore
    }
  }

  const internalDomainPatterns = input.tune.internalDomains.map(globToHostRegex);
  const customPatterns = input.tune.customPatterns.map((cp) => ({
    name: cp.name,
    regex: new RegExp(cp.regex, "g"),
    class: cp.class,
  }));

  return {
    gitleaks: input.detection.gitleaks,
    fastPiiRegex: input.detection.fastPiiRegex,
    presidio: input.detection.presidio,
    presidioCommand: input.presidioCommand,
    tuned: { envKeys, internalDomainPatterns, customPatterns },
    allowlist: new Set(input.allow),
    genericCredentialEntropy: input.detection.entropy?.genericCredential ?? 2.7,
  };
}

export function detect(text: string, cfg: EngineConfig): DetectionSpan[] {
  const spans: DetectionSpan[] = [];
  if (cfg.gitleaks) spans.push(...detectSecrets(text, cfg.allowlist, cfg.genericCredentialEntropy));
  if (cfg.fastPiiRegex) spans.push(...detectFastPii(text, cfg.allowlist));
  spans.push(...detectTuned(text, cfg.tuned, cfg.allowlist));
  if (cfg.presidio) {
    spans.push(...detectPresidio(text, { enabled: true, command: cfg.presidioCommand }));
  }
  return mergeSpans(spans);
}
