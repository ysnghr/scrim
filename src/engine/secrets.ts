// Secret detection: runs Gitleaks-style rules and emits spans pointing at the
// secret VALUE (not its surrounding key=) so the tokenizer replaces only the
// sensitive bytes. Drops matches whose value is in the allowlist or fails the
// rule's entropy threshold.
//
// The `generic-credential-assignment` rule is special: it routes through
// acceptGenericCredential() so a placeholder denylist + value-shape filters
// run alongside (and in front of) the entropy check. The entropy threshold
// for that rule is policy-tunable; every other rule uses its own static
// `entropy` field.

import { SECRET_RULES, shannonEntropy } from "./rules/secrets-rules.js";
import { IMPORTED_SECRET_RULES } from "./rules/gitleaks-imported-rules.js";
import {
  acceptGenericCredential,
  DEFAULT_GENERIC_CREDENTIAL_ENTROPY,
} from "./rules/generic-credential-filters.js";
import type { DetectionSpan } from "./spans.js";

const GENERIC_CRED_RULE_ID = "generic-credential-assignment";

// Core rules first, then imported. Within the "secrets" class, merge picks the
// earlier+longer span on overlap (see spans.ts), so order = precedence. Each
// rule's regex is compiled once at module load and re-used across calls;
// `lastIndex` is reset explicitly at the start of every scan. Safe because
// Node runs scan() synchronously to completion.
const ALL_SECRET_RULES = [...SECRET_RULES, ...IMPORTED_SECRET_RULES].map((rule) => ({
  ...rule,
  re: new RegExp(rule.pattern.source, rule.pattern.flags),
}));

export function detectSecrets(
  text: string,
  allowlist: Set<string>,
  genericCredentialEntropy: number = DEFAULT_GENERIC_CREDENTIAL_ENTROPY,
): DetectionSpan[] {
  const out: DetectionSpan[] = [];
  for (const rule of ALL_SECRET_RULES) {
    const re = rule.re;
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      const value = m[1] ?? m[0];
      if (!value) {
        if (m.index === re.lastIndex) re.lastIndex++;
        continue;
      }
      if (allowlist.has(value)) continue;

      if (rule.id === GENERIC_CRED_RULE_ID) {
        if (!acceptGenericCredential(value, { entropyThreshold: genericCredentialEntropy })) continue;
      } else if (rule.entropy !== undefined && shannonEntropy(value) < rule.entropy) {
        continue;
      }

      // Locate the captured group (group 1) within the full match so we tokenize
      // only the value, not the leading key/quote.
      const fullStart = m.index;
      const valueStart = m[1] !== undefined ? text.indexOf(value, fullStart) : fullStart;
      if (valueStart < 0) continue;
      out.push({
        start: valueStart,
        end: valueStart + value.length,
        class: rule.class,
        ruleId: rule.id,
      });

      if (m.index === re.lastIndex) re.lastIndex++;
    }
  }
  return out;
}
