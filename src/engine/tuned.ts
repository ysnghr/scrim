// Repo-tuned detection.
//
// Three knobs from policy.yml that cut false positives by teaching the engine
// about THIS project:
//   1. env_keys_from — values assigned to keys named here are tokenized as secrets.
//      The keys are loaded from files like .env.example at policy-build time.
//   2. internal_domains — globs like "*.internal" matched as internal_hostnames.
//   3. custom_patterns — user-supplied regex/class pairs.

import type { DetectionSpan } from "./spans.ts";

export interface TunedConfig {
  envKeys: Set<string>;
  internalDomainPatterns: RegExp[];
  customPatterns: { name: string; regex: RegExp; class: string }[];
}

// Parse .env.example-style content into a set of key names.
// Accepts `KEY=value`, `KEY = value`, `export KEY=value`, and ignores comments/blanks.
export function parseEnvKeys(content: string): Set<string> {
  const keys = new Set<string>();
  for (const line of content.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const m = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/.exec(trimmed);
    if (m && m[1]) keys.add(m[1]);
  }
  return keys;
}

// Convert a hostname glob ("*.internal", "*.corp.example.com") into a regex that
// matches a fully-qualified hostname inside arbitrary text.
export function globToHostRegex(glob: string): RegExp {
  // Escape regex specials, then turn '*' into a label/segment matcher.
  // '*' matches one or more host-label characters; multiple '*' allowed.
  const escaped = glob.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, "[A-Za-z0-9\\-]+");
  return new RegExp(`\\b${escaped}\\b`, "g");
}

function scan(text: string, re: RegExp, klass: string, ruleId: string): DetectionSpan[] {
  const out: DetectionSpan[] = [];
  const compiled = new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g");
  let m: RegExpExecArray | null;
  while ((m = compiled.exec(text)) !== null) {
    const value = m[1] ?? m[0];
    if (!value) {
      if (m.index === compiled.lastIndex) compiled.lastIndex++;
      continue;
    }
    const start = m[1] !== undefined ? text.indexOf(value, m.index) : m.index;
    if (start < 0) continue;
    out.push({ start, end: start + value.length, class: klass, ruleId });
  }
  return out;
}

export function detectTuned(text: string, cfg: TunedConfig, allowlist: Set<string>): DetectionSpan[] {
  const out: DetectionSpan[] = [];

  // env keys: KEY=value or KEY: value, on a line, capture the value
  if (cfg.envKeys.size > 0) {
    const alternation = Array.from(cfg.envKeys)
      .map((k) => k.replace(/[.+?^${}()|[\]\\]/g, "\\$&"))
      .join("|");
    const re = new RegExp(`\\b(?:${alternation})\\s*[:=]\\s*["']?([^\\s"'#]+)["']?`, "g");
    out.push(...scan(text, re, "secrets", "tuned-env-key"));
  }

  // internal domains
  for (const re of cfg.internalDomainPatterns) {
    out.push(...scan(text, re, "internal_hostnames", "tuned-internal-domain"));
  }

  // user-supplied custom patterns
  for (const cp of cfg.customPatterns) {
    out.push(...scan(text, cp.regex, cp.class, `tuned-custom:${cp.name}`));
  }

  return out.filter((s) => !allowlist.has(text.slice(s.start, s.end)));
}
